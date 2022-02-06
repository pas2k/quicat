package quicat

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"

	"github.com/lucas-clemente/quic-go"
)

type QuicConnMode int

type QuicSocketBehavior int

const (
	ActiveQuicConnMode QuicConnMode = iota
	PassiveQuicConnMode
	UnknownQuicConnMode

	ListenQuicSocketBehavior QuicSocketBehavior = iota
	TunnelQuicSocketBehavior
)

func parseQuicProto(proto string) (mode QuicConnMode, allowMultiple bool) {
	switch proto {
	case "quicactive":
		return ActiveQuicConnMode, true
	case "quiconeactive":
		return ActiveQuicConnMode, false
	case "quicpassive":
		return PassiveQuicConnMode, true
	case "quiconepassive":
		return PassiveQuicConnMode, false
	default:
		return UnknownQuicConnMode, false
	}
}

type quicSession struct {
	parent *quicConnector
	sess   quic.Session
	cfg    *Command
}

func (qs *quicSession) OpenAnother(ctx context.Context) (io.ReadWriteCloser, finalError, bool) {
	if !qs.parent.allowMultiple {
		if qs.parent.alreadyUsed {
			return nil, EOF, false
		}
		qs.parent.alreadyUsed = true
	}
	switch qs.parent.sockBehavior {
	case ListenQuicSocketBehavior:
		stream, err := qs.sess.AcceptStream(ctx)
		if err != nil {
			return stream, wrapError(err, false), false
		}
		if qs.cfg.SignalStream {
			input := []byte{0}
			i, err := stream.Read(input)
			if err != nil {
				stream.Close()
				return nil, wrapError(err, false), false
			}
			if i != 1 {
				stream.Close()
				return nil, wrapError(io.ErrShortWrite, false), false
			}
			if input[0] != 0 {
				stream.Close()
				return nil, wrapError(errors.New("Unexpected stream signal"), false), false
			}
		}
		return stream, nil, !qs.parent.allowMultiple
	case TunnelQuicSocketBehavior:
		stream, err := qs.sess.OpenStream()
		if err != nil {
			return stream, wrapError(err, false), false
		}
		if qs.cfg.SignalStream {
			_, err := stream.Write([]byte{0})
			if err != nil {
				stream.Close()
				return nil, wrapError(io.ErrShortWrite, false), false
			}
		}
		return stream, nil, !qs.parent.allowMultiple
	default:
		panic("Unexpected behavior")
	}
}

func (qc *quicConnector) makeTlsConfig() *tls.Config {
	ret := &tls.Config{
		NextProtos:         []string{qc.cfg.NextProto},
		InsecureSkipVerify: qc.tls.Insecure,
		RootCAs:            qc.tls.RootCAs,
		ClientCAs:          qc.tls.ClientCAs,
	}
	if qc.tls.ClientCAs != nil && len(qc.tls.ClientCAs.Subjects()) != 0 {
		ret.ClientAuth = tls.RequireAndVerifyClientCert
	}

	if len(qc.tls.Certificates) == 0 {
		// generate TLS certificate
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		mbpanic(err)
		template := x509.Certificate{SerialNumber: big.NewInt(1)}
		certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
		mbpanic(err)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
		mbpanic(err)
		ret.Certificates = []tls.Certificate{tlsCert}
	} else {
		ret.Certificates = qc.tls.Certificates
	}

	return ret
}

type qsResult struct {
	stream io.ReadWriteCloser
	err    finalError
	isLast bool
}

type quicConnector struct {
	hostPort      string
	alreadyUsed   bool
	allowMultiple bool
	multiQuic     bool
	sockBehavior  QuicSocketBehavior
	connMode      QuicConnMode

	cfg *Command
	tls TlsConfig

	streams    chan qsResult
	connTokens chan context.Context
}

// Active connections support single active connection
// Passive connections accept sessions and put those into the pool
func (qc *quicConnector) StartConnecting() {
	var ctx = context.Background()
	var err error
	var ok bool
	var listener quic.Listener
	tokenResolved := true

	defer close(qc.streams)

	if qc.connMode == PassiveQuicConnMode {
		// Listen early
		listener, err = quic.ListenAddr(qc.hostPort, qc.makeTlsConfig(), &quic.Config{KeepAlive: true})
		// On listen error, crash, as it's unrecoverable
		if err != nil {
			log.Fatalln("Failed to listen on ", qc.hostPort, ": ", err)
			return
		}
	}

	wasEverEstablished := false

	for {
	quicConnLoop:
		for {
			if tokenResolved {
				if ctx, ok = <-qc.connTokens; !ok {
					return
				}
				tokenResolved = false
			}
			if wasEverEstablished && !qc.multiQuic {
				return
			}
			var sess quic.Session
			if qc.connMode == ActiveQuicConnMode {
				sess, err = quic.DialAddr(qc.hostPort, qc.makeTlsConfig(), &quic.Config{KeepAlive: true})
				if err != nil {
					qc.streams <- qsResult{stream: nil, err: wrapError(err, false), isLast: false}
					tokenResolved = true
					continue quicConnLoop
				}
			} else {
				sess, err = listener.Accept(ctx)
				if err != nil {
					qc.streams <- qsResult{stream: nil, err: wrapError(err, false), isLast: false}
					tokenResolved = true
					continue quicConnLoop
				}
			}

			qs := &quicSession{
				parent: qc,
				sess:   sess,
				cfg:    qc.cfg,
			}
			wasEverEstablished = true

		quicSessLoop:
			for {
				if tokenResolved {
					if ctx, ok = <-qc.connTokens; !ok {
						return
					}
					tokenResolved = false
				}
				stream, err, last := qs.OpenAnother(ctx)

				if werr, ok := err.(*wrappedFinalError); ok {
					if _, ok := werr.e.(*quic.IdleTimeoutError); ok {
						qc.cfg.Logln("Closing session:", err)
						break quicSessLoop
					}
					if _, ok := werr.e.(*quic.HandshakeTimeoutError); ok {
						qc.cfg.Logln("Closing session:", err)
						break quicSessLoop
					}
				}

				qc.streams <- qsResult{stream: stream, err: err, isLast: last}
				tokenResolved = true
				if last {
					return
				}
				if err != nil && err.IsFinal() {
					break quicSessLoop
				}
			}

		}
	}
}

func (qs *quicConnector) Info() slInfo {
	if qs.connMode == PassiveQuicConnMode {
		ses := 5
		// Less than TCP server
		if qs.sockBehavior == TunnelQuicSocketBehavior {
			ses += 1
		}
		// When multiquic, user doesn't care for multiconnections
		if qs.multiQuic {
			ses -= 2
		}
		return slInfo{
			sideEffectsSize: ses,
		}
	}
	// Less than TCP client
	ses := 40
	if qs.sockBehavior == ListenQuicSocketBehavior {
		ses -= 1
	}
	if qs.sockBehavior == TunnelQuicSocketBehavior {
		ses += 1
	}
	// When multiquic, user doesn't care for multiconnections
	if qs.multiQuic {
		ses -= 3
	}
	return slInfo{
		sideEffectsSize: ses,
	}
}

func (qc *quicConnector) OpenAnother(ctx context.Context) (io.ReadWriteCloser, finalError, bool) {
	qc.connTokens <- ctx
	res, ok := <-qc.streams
	if !ok {
		return nil, EOF, true
	}
	return res.stream, res.err, res.isLast
}

func (a *Command) createQuic(tlsCfg TlsConfig, connMode QuicConnMode, multiQuic bool, sockBehavior QuicSocketBehavior, hostPort string, allowMultiple bool) (socketLike, error) {
	qc := &quicConnector{
		connMode:      connMode,
		sockBehavior:  sockBehavior,
		allowMultiple: allowMultiple,
		hostPort:      hostPort,
		multiQuic:     multiQuic,
		cfg:           a,
		tls:           tlsCfg,
		streams:       make(chan qsResult),
		connTokens:    make(chan context.Context),
	}
	go qc.StartConnecting()
	return qc, nil
}
