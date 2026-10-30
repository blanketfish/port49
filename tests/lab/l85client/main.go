// Command l85client is the device in lab entry L85 (spec §15): a TACACS+ client that runs in a
// container behind the FRR router and logs in at the anycast address. It reads one JSON document
// from stdin, {"key": ..., "token": ..., "user": ...}, and prints only a closed vocabulary: pass,
// fail:<kind> and the per-second lines the harness (tests/lab/l85_test.go, via tests/shapes/l85)
// parses. It never prints, logs or puts in an argument the key or the token.
//
//	l85client probe   -addr A              one login on one connection: pass | fail:<kind>
//	l85client loop    -addr A -for D       one login a second, a retry at once if it fails:
//	                                       "<second> <first> <retry>", each pass | fail:<kind> | -
//	l85client session -addr A -for D       one connection with the single-connection flag and a login
//	                                       a second on it: "ok <second>" per login, then
//	                                       "end <second> closed|reset|timeout|error|deadline"
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// Creds is the device's key and a login's password (a broker-minted token) and user.
type Creds struct{ Key, Token, User string }

// kind is the closed alphabet of why a login did not complete.
func kind(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "closed"
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	}
	return "error"
}

var sessionID uint32 = 0x85000000

// exchange sends one PAP login as a new session on conn and returns the reply's status.
func exchange(conn net.Conn, c Creds, single bool) (uint8, error) {
	sessionID++
	body := wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte(c.User), Port: []byte("ssh"), RemAddr: []byte("198.51.100.4"),
		Data: []byte(c.Token)}.Encode()
	h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, SessionID: sessionID, Length: uint32(len(body))}
	if single {
		h.Flags |= wire.FlagSingleConnect
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(append(h.Encode(), wire.Obfuscate(h, []byte(c.Key), body)...)); err != nil {
		return 0, err
	}
	hb := make([]byte, wire.HeaderLen)
	if _, err := io.ReadFull(conn, hb); err != nil {
		return 0, err
	}
	rh, err := wire.DecodeHeader(hb)
	if err != nil {
		return 0, err
	}
	rb := make([]byte, rh.Length)
	if _, err := io.ReadFull(conn, rb); err != nil {
		return 0, err
	}
	r, err := wire.DecodeAuthenReply(wire.Obfuscate(rh, []byte(c.Key), rb))
	if err != nil {
		return 0, err
	}
	return r.Status, nil
}

func result(status uint8, err error) string {
	switch {
	case err != nil:
		return "fail:" + kind(err)
	case status == wire.AuthenStatusPass:
		return "pass"
	}
	return fmt.Sprintf("fail:status_%d", status)
}

// Probe is one login on its own connection.
func Probe(addr string, c Creds) string {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "fail:" + kind(err)
	}
	defer conn.Close()
	return result(exchange(conn, c, false))
}

// Loop is a login a second for d, each on a new connection, with an immediate retry of one that
// failed. every is the interval, a second in the lab.
func Loop(out io.Writer, addr string, c Creds, d, every time.Duration) {
	start := time.Now()
	for n := 0; time.Since(start) < d; n++ {
		next := start.Add(time.Duration(n+1) * every)
		first, retry := Probe(addr, c), "-"
		if first != "pass" {
			retry = Probe(addr, c)
		}
		fmt.Fprintf(out, "%d %s %s\n", n, first, retry)
		time.Sleep(time.Until(next))
	}
}

// Session is one connection with the single-connection flag, a login a second on it, until it fails
// or d has passed.
func Session(out io.Writer, addr string, c Creds, d, every time.Duration) {
	start := time.Now()
	sec := func() int { return int(time.Since(start) / every) }
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		fmt.Fprintf(out, "end %d %s\n", sec(), kind(err))
		return
	}
	defer conn.Close()
	for time.Since(start) < d {
		st, err := exchange(conn, c, true)
		if err != nil {
			fmt.Fprintf(out, "end %d %s\n", sec(), kind(err))
			return
		}
		if st != wire.AuthenStatusPass {
			fmt.Fprintf(out, "end %d error\n", sec())
			return
		}
		fmt.Fprintf(out, "ok %d\n", sec())
		time.Sleep(every)
	}
	fmt.Fprintf(out, "end %d deadline\n", sec())
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: l85client probe|loop|session -addr A [-for D]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	addr := fs.String("addr", "", "the anycast address, host:port")
	dur := fs.Duration("for", time.Minute, "how long")
	fs.Parse(os.Args[2:])
	var c Creds
	var raw struct{ Key, Token, User string }
	if err := json.NewDecoder(os.Stdin).Decode(&raw); err != nil || raw.Key == "" || raw.Token == "" {
		fmt.Fprintln(os.Stderr, "l85client: stdin is not {key, token, user}")
		os.Exit(2)
	}
	c = Creds(raw)
	if c.User == "" {
		c.User = "alice"
	}
	switch os.Args[1] {
	case "probe":
		fmt.Println(Probe(*addr, c))
	case "loop":
		Loop(os.Stdout, *addr, c, *dur, time.Second)
	case "session":
		Session(os.Stdout, *addr, c, *dur, time.Second)
	default:
		fmt.Fprintln(os.Stderr, "l85client: unknown command")
		os.Exit(2)
	}
}
