package quicat

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type slInfo struct {
	sideEffectsSize int
}

type finalError interface {
	error
	IsFinal() bool
}

type wrappedFinalError struct {
	e     error
	final bool
}

func (wfe *wrappedFinalError) IsFinal() bool {
	return wfe.final
}

func (wfe *wrappedFinalError) Error() string {
	return wfe.e.Error()
}

func wrapError(e error, final bool) finalError {
	if e == nil {
		return nil
	}
	return &wrappedFinalError{e, final}
}

var EOF = wrapError(io.EOF, true)
var OperationNotSupported = wrapError(io.ErrNoProgress, true)

func mbpanic(err error) {
	if err != nil {
		panic(err)
	}
}

func (a *Command) createSocketConnector(tlsCfg TlsConfig, proto string, hostPort string, allowMultiple bool) (socketLike, error) {

	connMode, multiQuic := parseQuicProto(proto)
	if connMode != UnknownQuicConnMode {
		return a.createQuic(tlsCfg, connMode, multiQuic, TunnelQuicSocketBehavior, hostPort, allowMultiple)
	}
	switch proto {
	case "tcp":
		return &tcpConnector{proto: proto, hostPort: hostPort, allowMultiple: allowMultiple}, nil
	default:
		log.Fatalln("Proto " + proto + " is not supported")
		panic(nil)
	}
}

func (a *Command) createSocketServer(tlsCfg TlsConfig, proto string, hostPort string, allowMultiple bool) (socketLike, error) {
	connMode, multiQuic := parseQuicProto(proto)
	if connMode != UnknownQuicConnMode {
		return a.createQuic(tlsCfg, connMode, multiQuic, ListenQuicSocketBehavior, hostPort, allowMultiple)
	}
	switch proto {
	case "tcp":
		addr, err := net.ResolveTCPAddr(proto, hostPort)
		if err != nil {
			return nil, err
		}
		listener, err := net.ListenTCP(proto, addr)
		if err != nil {
			return nil, err
		}
		return &tcpServer{listener: listener, allowMultiple: allowMultiple}, err
	default:
		log.Fatalln("Proto " + proto + " is not supported")
		panic(nil)
	}
}

func (a *Command) createSocketLike(tlsCfg TlsConfig, urlString string) (socketLike, error) {
	if urlString == "stdio" {
		return &compositeRwc{r: os.Stdin, w: os.Stdout, allowMultiple: true}, nil
	}
	if urlString == "stdin" {
		return &compositeRwc{r: os.Stdin, allowMultiple: true}, nil
	}
	if urlString == "stdout" {
		return &compositeRwc{w: os.Stdout, allowMultiple: true}, nil
	}
	u, err := url.Parse(urlString)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(u.Scheme, "-")
	if len(parts) == 3 {
		if parts[0] == "quic" {
			parts = []string{parts[0] + parts[1], parts[2]}
		}
	}
	if len(parts) != 2 {
		return nil, errors.New("Scheme should contain two dash-separated parts")
	}
	switch parts[0] {
	case "file":
		switch parts[1] {
		case "r":
			f, err := os.Open(u.Path)
			if err != nil {
				return nil, err
			}
			return &compositeRwc{r: f, c: f}, nil
		case "w":
			f, err := os.Create(u.Path)
			if err != nil {
				return nil, err
			}
			return &compositeRwc{w: f, c: f}, nil
		default:
			return nil, errors.New("Unsupported file mode: " + parts[1])
		}
	default:
		switch parts[1] {
		case "listen":
			fallthrough
		case "accept":
			return a.createSocketServer(tlsCfg, parts[0], u.Host, parts[1] == "listen")
		case "tunnel":
			fallthrough
		case "connect":
			return a.createSocketConnector(tlsCfg, parts[0], u.Host, parts[1] == "tunnel")
		}
		log.Fatalln("Access method " + parts[1] + " is not supported")
		panic(nil)
	}
}

type doneReporter struct {
	l    sync.Locker
	cond *sync.Cond
	done bool
}

func (dr *doneReporter) Report() {
	dr.l.Lock()
	dr.done = true
	dr.cond.Broadcast()
	dr.l.Unlock()
}

func (a *Command) Logln(args ...interface{}) {
	if !a.Quiet {
		log.Println(args...)
	}
}

func (a *Command) Fatalln(args ...interface{}) {
	if a.Quiet {
		os.Exit(1)
	} else {
		log.Fatalln(args...)
	}
}

type TlsConfig struct {
	RootCAs      *x509.CertPool
	ClientCAs    *x509.CertPool
	Certificates []tls.Certificate
	Insecure     bool
}

type Command struct {
	Urls         []string
	RetryTimeout int
	Quiet        bool
	NextProto    string
	Simultaneous bool
	Verbose      bool
	SignalStream bool

	SrcTls, DstTls TlsConfig
}

func (a *Command) Main() {

	srcSock, err := a.createSocketLike(a.SrcTls, a.Urls[0])
	if err != nil {
		a.Fatalln("While creating src: ", err)
	}
	dstSock, err := a.createSocketLike(a.DstTls, a.Urls[1])
	if err != nil {
		a.Fatalln("While creating dst: ", err)
	}

	srcStreamRequests := make(chan struct{}, 1)
	dstStreamRequests := make(chan struct{}, 1)
	srcStreams := make(chan io.ReadWriteCloser)
	dstStreams := make(chan io.ReadWriteCloser)

	globalCtx := context.Background()

	feedChan := func(sl socketLike, slc chan io.ReadWriteCloser, requests chan struct{}) {
		for {
			_, ok := <-requests
			if !ok {
				close(slc)
				return
			}
		openOne:
			for {
				c, err, isLast := sl.OpenAnother(globalCtx)
				if err != nil {
					if err == EOF {
						close(slc)
						return
					} else {
						a.Logln(err)
					}
					if a.RetryTimeout < 0 {
						close(slc)
						return
					} else {
						time.Sleep(time.Duration(a.RetryTimeout) * time.Millisecond)
						continue
					}
				}
				slc <- c
				if isLast {
					close(slc)
					return
				}
				break openOne
			}

		}
	}
	go feedChan(srcSock, srcStreams, srcStreamRequests)
	go feedChan(dstSock, dstStreams, dstStreamRequests)

	oneDoneMutex := sync.Mutex{}
	var oneDone *doneReporter

pumpLoop:
	for {
		var srcStream io.ReadWriteCloser
		var dstStream io.ReadWriteCloser
		if a.Simultaneous {
			srcStreamRequests <- struct{}{}
			dstStreamRequests <- struct{}{}
			// Race effects when same
			select {
			case srcStream = <-srcStreams:
				if srcStream == nil {
					break pumpLoop
				}
				break
			case dstStream = <-dstStreams:
				if dstStream == nil {
					break pumpLoop
				}
				break
			}
		} else {
			srcStreamRequests <- struct{}{}
			srcStream = <-srcStreams
		}

		if dstStream == nil {
			dstStreamRequests <- struct{}{}
			dstStream = <-dstStreams
		}
		if srcStream == nil {
			srcStreamRequests <- struct{}{}
			srcStream = <-srcStreams
		}
		if dstStream == nil || srcStream == nil {
			if dstStream != nil {
				dstStream.Close()
			}
			if srcStream != nil {
				srcStream.Close()
			}
			break pumpLoop
		}
		if oneDone == nil {
			oneDone = &doneReporter{cond: sync.NewCond(&oneDoneMutex), l: &oneDoneMutex, done: false}
		}
		go pumpStream(srcStream, dstStream, oneDone)
	}
	close(srcStreamRequests)
	close(dstStreamRequests)
	// If we ever started something, wait at least one task to finish
	if oneDone != nil {
		oneDone.l.Lock()
		for !oneDone.done {
			oneDone.cond.Wait()
		}
		oneDone.l.Unlock()
	}

}
