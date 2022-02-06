package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	quicat "github.com/pas2k/quicat/quicatlib"
)

type SelectedPeer int

const (
	EverySelectedPeer SelectedPeer = iota
	SrcSelectedPeer
	DstSelectedPeer
)

type markerValue struct {
	onSet func() error
}

func (b *markerValue) Set(s string) error {
	return b.onSet()
}
func (b *markerValue) Get() interface{} { return false }
func (b *markerValue) String() string   { return "" }
func (b *markerValue) IsBoolFlag() bool { return true }

type multiValue struct {
	onSet func(val string) error
}

func (b *multiValue) Set(s string) error {
	return b.onSet(s)
}
func (b *multiValue) Get() interface{} { return "" }
func (b *multiValue) String() string   { return "" }

func main() {

	flags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(flags.Output(), "%s [flags] <src> <dst>\n\n", os.Args[0])
		fmt.Fprintf(flags.Output(), "  <src> and <dst> are either\n")
		fmt.Fprintf(flags.Output(), "  \t{stdio|stdin|stdout}\n")
		fmt.Fprintf(flags.Output(), "  \t{file-r|file-w}://<filename>\n")
		fmt.Fprintf(flags.Output(), "  \tquic-[one]{active|passive}-{listen|accept|connect|tunnel}://<hostname>:<port>\n")
		fmt.Fprintf(flags.Output(), "  \ttcp-{listen|accept|connect|tunnel}://<hostname>:<port>\n\n")
		fmt.Fprintf(flags.Output(), "  'accept' is the same as 'listen', but exits after the connection is closed. 'tunnel' is the same as 'connect', but can connect multiple times.\n")
		fmt.Fprintf(flags.Output(), "  'oneactive' is same as 'active', but exits after the connection is closed/timed out instead of listening/retrying (same with 'passive').\n\n")
		flags.PrintDefaults()
	}

	cmd := quicat.Command{}
	flags.IntVar(&cmd.RetryTimeout, "retry-delay", -1, "When positive, retry connections, inserting a delay (in ms) between each retry")
	flags.BoolVar(&cmd.Quiet, "quiet", false, "Don't print errors to stderr")

	flags.StringVar(&cmd.NextProto, "next-proto", "", "Specify TLS next proto, 'raw' or 'raw-sig' (-streamsig) by default")
	flags.BoolVar(&cmd.Simultaneous, "simultaneous", false, "Attempt connections to src and dst at the same time")
	flags.BoolVar(&cmd.SignalStream, "signalstream", true, "Signal streams by sending a (zero) character in a stream that just opened")

	selectedPeer := EverySelectedPeer
	flags.Var(&markerValue{func() error {
		selectedPeer = SrcSelectedPeer
		return nil
	}}, "src", "Following crypto arguments will only concern first (src) argument URI")
	flags.Var(&markerValue{func() error {
		selectedPeer = DstSelectedPeer
		return nil
	}}, "dst", "Following crypto arguments will only concern second (dst) argument URI")

	withPeers := func(what func(ctx *quicat.TlsConfig)) {
		switch selectedPeer {
		case EverySelectedPeer:
			what(&cmd.SrcTls)
			what(&cmd.DstTls)
		case SrcSelectedPeer:
			what(&cmd.SrcTls)
		case DstSelectedPeer:
			what(&cmd.DstTls)
		}
	}

	flags.Var(&multiValue{func(val string) error {
		certBytes, err := ioutil.ReadFile(val)
		if err != nil {
			return fmt.Errorf("While reading %v: %w", val, err)
		}
		cer, err := tls.X509KeyPair(certBytes, certBytes)
		if err != nil {
			return fmt.Errorf("While parsing %v: %w", val, err)
		}
		withPeers(func(ctx *quicat.TlsConfig) {
			ctx.Certificates = append(ctx.Certificates, cer)
		})
		return nil
	}}, "keypair", "Certificate/key pair in a single PEM-encoded file")

	caHandler := func(poolAccessor func(cfg *quicat.TlsConfig) **x509.CertPool) func(val string) error {
		return func(val string) error {
			certBytes, err := ioutil.ReadFile(val)
			if err != nil {
				return fmt.Errorf("While reading %v: %w", val, err)
			}
			cer, err := x509.ParseCertificate(certBytes)
			if err != nil {
				return fmt.Errorf("While parsing %v: %w", val, err)
			}
			withPeers(func(ctx *quicat.TlsConfig) {
				poolPtr2 := poolAccessor(ctx)
				if *poolPtr2 == nil {
					*poolPtr2 = x509.NewCertPool()
				}
				(*poolPtr2).AddCert(cer)
			})
			return nil
		}
	}

	flags.Var(&markerValue{func() error {
		withPeers(func(ctx *quicat.TlsConfig) {
			ctx.Insecure = true
		})
		return nil
	}}, "insecure", "Insecure, don't check remote cert validity. Vulnerable to MITM.")

	flags.Var(&multiValue{caHandler(func(cfg *quicat.TlsConfig) **x509.CertPool {
		return &cfg.RootCAs
	})}, "ca", "Use this CA for cert checking, can be specified multiple times")

	flags.Var(&multiValue{caHandler(func(cfg *quicat.TlsConfig) **x509.CertPool {
		return &cfg.ClientCAs
	})}, "clientca", "Present this certificate to peers, can be specified multiple times")

	flags.Parse(os.Args[1:])

	cmd.Urls = flags.Args()
	if len(cmd.Urls) < 2 {
		flags.Usage()
		os.Exit(1)
	}

	if cmd.NextProto == "" {
		if cmd.SignalStream {
			cmd.NextProto = "raw-sig"
		} else {
			cmd.NextProto = "raw"
		}
	}

	cmd.Main()
}
