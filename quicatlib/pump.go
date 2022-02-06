package quicat

import "io"

func pumpUni(rdr io.Reader, w io.Writer, globalStop, stop chan error) error {
	ret := pumpUni1(rdr, w, globalStop)
	if ret != OperationNotSupported {
		close(stop)
	}
	return ret
}

func pumpUni1(rdr io.Reader, w io.Writer, globalStop chan error) error {
	buf := make([]byte, 8192)
	for {
		select {
		case <-globalStop:
			return nil
		default:
		}
		n, err := rdr.Read(buf)
		if err != nil {
			return err
		}
		select {
		case <-globalStop:
			return nil
		default:
		}
		n, err = w.Write(buf[:n])
		if err != nil {
			return err
		}
	}
}

func pumpStream(p1, p2 io.ReadWriteCloser, done *doneReporter) {
	stop12 := make(chan error)
	stop21 := make(chan error)
	globalStop := make(chan error)
	go func() {
		select {
		case <-stop12:
			close(globalStop)
		case <-stop21:
			close(globalStop)
		}
		p1.Close()
		p2.Close()
		done.Report()
	}()
	go pumpUni(p1, p2, globalStop, stop12)
	go pumpUni(p2, p1, globalStop, stop21)
	<-globalStop
}
