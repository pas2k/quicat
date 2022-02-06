package quicat

import (
	"context"
	"io"
	"net"
	"sync"
)

type socketLike interface {
	// When isLast is passed, error is io.Eof
	OpenAnother(ctx context.Context) (stream io.ReadWriteCloser, err finalError, last bool)
	Info() slInfo
}

type compositeRwc struct {
	r             io.Reader
	w             io.Writer
	c             io.Closer
	allowMultiple bool
	alreadyUsed   bool
	info          slInfo
	useMutex      sync.Mutex
	useMutexChan  chan struct{}
}

func (ts *compositeRwc) Info() slInfo {
	return ts.info
}

func (i *compositeRwc) Close() error {
	if i.c != nil {
		i.c.Close()
	}
	i.useMutex.Lock()
	close(i.useMutexChan)
	i.useMutexChan = nil
	i.useMutex.Unlock()
	return nil
}

func (i *compositeRwc) Read(buf []byte) (int, error) {
	if i.r == nil {
		return 0, io.ErrClosedPipe
	}
	return i.r.Read(buf)
}

func (i *compositeRwc) Write(buf []byte) (int, error) {
	if i.w == nil {
		return 0, io.ErrShortWrite
	}
	return i.w.Write(buf)
}

func (cr *compositeRwc) OpenAnother(ctx context.Context) (io.ReadWriteCloser, finalError, bool) {
	if !cr.allowMultiple && cr.alreadyUsed {
		return nil, EOF, false
	}
	cr.useMutex.Lock()
	useMutexChan := cr.useMutexChan
	cr.useMutex.Unlock()
	if useMutexChan != nil {
		<-useMutexChan
	}
	cr.useMutexChan = make(chan struct{})
	cr.alreadyUsed = true
	return cr, nil, false
}

type tcpConnector struct {
	proto, hostPort string
	alreadyUsed     bool
	allowMultiple   bool
}

func (ts *tcpConnector) Info() slInfo {
	if ts.allowMultiple {
		return slInfo{
			sideEffectsSize: 49,
		}
	}
	return slInfo{
		sideEffectsSize: 50,
	}
}

func (ts *tcpConnector) OpenAnother(ctx context.Context) (io.ReadWriteCloser, finalError, bool) {
	if !ts.allowMultiple {
		if ts.alreadyUsed {
			return nil, EOF, false
		}
		ts.alreadyUsed = true
	}
	addr, err := net.ResolveTCPAddr(ts.proto, ts.hostPort)
	if err != nil {
		// Let's treat resolve errors as final, but repeatable
		return nil, wrapError(err, true), true
	}
	conn, err := net.DialTCP(ts.proto, nil, addr)
	if err != nil {
		return nil, wrapError(err, false), !ts.allowMultiple
	}
	return conn, nil, !ts.allowMultiple
}

type tcpServer struct {
	listener      *net.TCPListener
	alreadyUsed   bool
	allowMultiple bool
}

func (ts *tcpServer) Info() slInfo {
	return slInfo{
		sideEffectsSize: 10,
	}
}

func (ts *tcpServer) OpenAnother(ctx context.Context) (io.ReadWriteCloser, finalError, bool) {
	if !ts.allowMultiple {
		if ts.alreadyUsed {
			return nil, EOF, false
		}
		ts.alreadyUsed = true
	}
	acc, err := ts.listener.AcceptTCP()
	return acc, wrapError(err, true), !ts.allowMultiple
}
