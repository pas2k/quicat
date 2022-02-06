## Quicat -- a socat-like utility for working with QUIC

This is a utility that I occasionally use for building secure-enough tunnels on flaky connections and ISPs that have TCP-breaking standards violations.

Please treat it as a pre-alpha, as it might (and probably does) contain bugs.

## Usage

    Usage of quicat:
    quicat [flags] <src> <dst>

    <src> and <dst> are either
            {stdio|stdin|stdout}
            {file-r|file-w}://<filename>
            quic-[one]{active|passive}-{listen|accept|connect|tunnel}://<hostname>:<port>
            tcp-{listen|accept|connect|tunnel}://<hostname>:<port>

    'accept' is the same as 'listen', but exits after the connection is closed. 'tunnel' is the same as 'connect', but can connect multiple times.
    'oneactive' is same as 'active', but exits after the connection is closed/timed out instead of listening/retrying (same with 'passive').

    -ca value
            Use this CA for cert checking, can be specified multiple times
    -clientca value
            Present this certificate to peers, can be specified multiple times
    -dst
            Following crypto arguments will only concern second (dst) argument URI
    -insecure
            Insecure, don't check remote cert validity. Vulnerable to MITM.
    -keypair value
            Certificate/key pair in a single PEM-encoded file
    -next-proto string
            Specify TLS next proto, 'raw' or 'raw-sig' (-streamsig) by default
    -quiet
            Don't print errors to stderr
    -retry-delay int
            When positive, retry connections, inserting a delay (in ms) between each retry (default -1)
    -signalstream
            Signal streams by sending a (zero) character in a stream that just opened (default true)
    -simultaneous
            Attempt connections to src and dst at the same time
    -src
            Following crypto arguments will only concern first (src) argument URI

## Known issues

* quicat only supports a single QUIC session at a time. Until several dispatching strategies are implemented, this is by design. Wait for the QUIC session to timeout or send an application error to it before connecting again.
