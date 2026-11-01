// Command tacacs-tls-client is L72's reference RFC 9887 client: TACACS+
// over TLS with Go's crypto/tls, one PAP login per connection, and a JSON
// line per connection saying what the server did. It never prints the token
// it reads.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/blanketfish/port49/internal/tacacs/wire"
)

type result struct {
	Conn      int    `json:"conn"`
	Handshake string `json:"handshake"`
	Error     string `json:"error,omitempty"`
	Resumed   bool   `json:"resumed"`
	Status    string `json:"status"`
	Flags     int    `json:"flags"`
	After     string `json:"after"`
	ClosedMS  int64  `json:"closed_ms"`
}

// firstTicket offers the first ticket it was given at every connection.
type firstTicket struct {
	mu sync.Mutex
	cs *tls.ClientSessionState
}

func (c *firstTicket) Get(string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cs, c.cs != nil
}

func (c *firstTicket) Put(_ string, cs *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cs == nil && cs != nil {
		c.cs = cs
	}
}

func main() {
	addr := flag.String("addr", "", "host:port")
	source := flag.String("source", "", "local address to connect from")
	certFile := flag.String("cert", "", "client certificate (PEM); none sends no certificate")
	keyFile := flag.String("key", "", "client key (PEM)")
	caFile := flag.String("ca", "", "CA that signs the server's certificate")
	serverName := flag.String("server-name", "", "SNI and the name the server's certificate is checked against")
	user := flag.String("user", "alice", "username")
	tokenFile := flag.String("token-file", "", "file holding the password; read, never printed")
	tls12 := flag.Bool("max-tls12", false, "offer TLS 1.2 only")
	obfuscated := flag.Bool("obfuscated", false, "send the login with the unencrypted flag clear")
	plain := flag.Bool("plain", false, "no TLS: send one RFC 8907 header and four body bytes")
	silent := flag.Bool("silent", false, "connect over TCP and send nothing; report when the server closes")
	count := flag.Int("count", 1, "connections, one after another")
	replay := flag.Bool("replay", false, "offer the first session ticket at every connection")
	flag.Parse()

	var password []byte
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "token-file:", err) // the path's error, never its contents
			os.Exit(2)
		}
		password = []byte(strings.TrimSpace(string(b)))
	}
	cfg := &tls.Config{ServerName: *serverName, MinVersion: tls.VersionTLS12}
	if *tls12 {
		cfg.MaxVersion = tls.VersionTLS12
	}
	if *caFile != "" {
		b, err := os.ReadFile(*caFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ca:", err)
			os.Exit(2)
		}
		cfg.RootCAs = x509.NewCertPool()
		cfg.RootCAs.AppendCertsFromPEM(b)
	}
	if *certFile != "" {
		c, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cert:", err)
			os.Exit(2)
		}
		cfg.Certificates = []tls.Certificate{c}
	}
	if *replay {
		cfg.ClientSessionCache = &firstTicket{}
	} else {
		cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if *source != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(*source)}
	}
	enc := json.NewEncoder(os.Stdout)
	for i := 1; i <= *count; i++ {
		enc.Encode(one(i, dialer, *addr, cfg, *user, password, *obfuscated, *plain, *silent))
	}
}

func one(i int, d *net.Dialer, addr string, cfg *tls.Config, user string, password []byte,
	obfuscated, plain, silent bool) result {
	r := result{Conn: i, Status: "none"}
	raw, err := d.Dial("tcp", addr)
	if err != nil {
		r.Handshake, r.Error = "error", err.Error()
		return r
	}
	defer raw.Close()
	start := time.Now()
	raw.SetDeadline(start.Add(10 * time.Second))
	if silent || plain {
		r.Handshake = "none"
		if plain {
			h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, SessionID: 1, Length: 4}
			raw.Write(append(h.Encode(), 0, 0, 0, 0))
		}
		r.After = after(raw)
		r.ClosedMS = time.Since(start).Milliseconds()
		return r
	}
	tc := tls.Client(raw, cfg)
	if err := tc.Handshake(); err != nil {
		r.Handshake, r.Error = "error", err.Error()
		return r
	}
	r.Handshake, r.Resumed = "ok", tc.ConnectionState().DidResume
	body := wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte(user), Port: []byte("tty0"), RemAddr: []byte("192.0.2.72"),
		Data: password}.Encode()
	flags := uint8(wire.FlagUnencrypted)
	if obfuscated {
		flags = 0
	}
	h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, Flags: flags, SessionID: 0x72, Length: uint32(len(body))}
	if _, err := tc.Write(append(h.Encode(), body...)); err != nil {
		r.Error = err.Error()
		r.After = "reset"
		return r
	}
	hb := make([]byte, wire.HeaderLen)
	if _, err := io.ReadFull(tc, hb); err != nil {
		r.Error = err.Error() // a TLS alert arrives here in TLS 1.3
		r.After = classify(err)
		r.ClosedMS = time.Since(start).Milliseconds()
		return r
	}
	rh, _ := wire.DecodeHeader(hb)
	rb := make([]byte, rh.Length)
	io.ReadFull(tc, rb)
	r.Flags = int(rh.Flags)
	if rep, err := wire.DecodeAuthenReply(rb); err == nil {
		r.Status = map[uint8]string{wire.AuthenStatusPass: "pass", wire.AuthenStatusFail: "fail",
			wire.AuthenStatusError: "error"}[rep.Status]
	}
	r.After = after(tc)
	r.ClosedMS = time.Since(start).Milliseconds()
	return r
}

// after reads once more and says how the server left the connection.
func after(c net.Conn) string {
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := c.Read(make([]byte, 1))
	return classify(err)
}

func classify(err error) string {
	var ne net.Error
	switch {
	case err == nil:
		return "open"
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	}
	return "error: " + err.Error()
}
