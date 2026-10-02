package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/daemon/admin"
)

// The client waits past port49d's own hold on the connection
// (admin.RevokeWait, admin.ListWait), so it is never the side that gives up
// on a revocation that goes on to finish and loses its report.
const (
	revokeWait = admin.RevokeWait + 5*time.Second
	listWait   = admin.ListWait + 5*time.Second
)

// maxCertFile bounds the --cert file read: a certificate is a few KiB, and
// a mistyped path (/dev/zero, a log) must not hang or exhaust the client.
const maxCertFile = 1 << 20

// revokeCmd is `port49 revoke` (spec §12; plan 7a): it asks port49d, over
// its admin socket, to revoke or lift a principal or one certificate, or to
// list the revocations in force.
func revokeCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", "/run/port49/port49d.sock", "port49d's admin_socket")
	principal := fs.String("principal", "", "the principal, as the log names it: user:alice@example.com")
	certFile := fs.String("cert", "", "a file holding the one certificate (PEM or DER); its issuer and serial are read from it")
	issuer := fs.String("cert-issuer", "", "the certificate's issuer, as the broker spells it (RFC 2253: CN=…,O=…)")
	serial := fs.String("cert-serial", "", "the certificate's serial, in hex")
	lift := fs.Bool("lift", false, "lift the revocation instead")
	list := fs.Bool("list", false, "list the revocations in force")
	mine := fs.Bool("mine", false, "end your own sessions and delete your own unspent tokens, through your agent; leaves no mark")
	viaAgent := fs.Bool("via-agent", false, "send the revocation to the broker through your agent, under your api: rights")
	device := fs.String("device", "", "with --mine or --via-agent: one device, by its inventory name")
	username := fs.String("username", "", "with --device: the device-facing username")
	agentSocket := fs.String("agent-socket", agent.SocketPath(), "your agent's socket")
	yes := fs.Bool("yes", false, "with --via-agent --principal: do not ask before revoking")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	if *mine || *viaAgent || *device != "" || *username != "" {
		switch {
		case *list || *lift || *certFile != "" || *issuer != "" || *serial != "":
			fmt.Fprintln(stderr, "port49 revoke: over the broker a revocation names --mine, --principal, or "+
				"--device and --username; lifting, listing and certificates are port49d's admin socket's (--socket)")
			return 2
		case *mine && *viaAgent, *mine && *principal != "":
			fmt.Fprintln(stderr, "port49 revoke: --mine names yourself; use --via-agent --principal for another")
			return 2
		case (*device == "") != (*username == ""):
			fmt.Fprintln(stderr, "port49 revoke: --device and --username go together")
			return 2
		case !*mine && !*viaAgent:
			// A key means one thing whatever the caller's rights (pre-flight I2).
			fmt.Fprintln(stderr, "port49 revoke: --device and --username go with --mine (your own session there) "+
				"or --via-agent (whoever's, under api: revoke_others)")
			return 2
		case !*mine && (*principal == "") == (*device == ""):
			fmt.Fprintln(stderr, "port49 revoke: --via-agent names --principal, or --device and --username")
			return 2
		}
		if *viaAgent && *principal != "" && !*yes && confirmTTY() && !confirmRevoke(*principal, stderr) {
			fmt.Fprintln(stderr, "port49 revoke: nothing was revoked")
			return 1
		}
		return revokeOverAgent(*agentSocket, api.RevokeRequest{Mine: *mine, Principal: *principal,
			Device: *device, Username: *username}, stdout, stderr)
	}
	// The flags are checked before the file is read: a usage error is
	// exit 2 whatever the file holds.
	if *list {
		if *principal != "" || *certFile != "" || *issuer != "" || *serial != "" || *lift {
			fmt.Fprintln(stderr, "port49 revoke: --list takes no principal, certificate or --lift")
			return 2
		}
		return askRevoke(*socket, admin.Request{Op: "revocations"}, listWait, stdout, stderr)
	}
	if *certFile != "" && (*issuer != "" || *serial != "") {
		fmt.Fprintln(stderr, "port49 revoke: --cert, or --cert-issuer and --cert-serial; not both")
		return 2
	}
	byCert := *certFile != "" || *issuer != "" || *serial != ""
	switch {
	case (*principal != "") == byCert:
		fmt.Fprintln(stderr, "port49 revoke: name a principal (--principal), or a certificate (--cert, or "+
			"--cert-issuer and --cert-serial); one of the two")
		return 2
	case *certFile == "" && byCert && (*issuer == "" || *serial == ""):
		fmt.Fprintln(stderr, "port49 revoke: a certificate is named by --cert-issuer and --cert-serial, both")
		return 2
	}
	req := admin.Request{Op: "revoke", Principal: *principal, CertIssuer: *issuer, CertSerial: *serial, Lift: *lift}
	if *certFile != "" {
		c, err := readCertificate(*certFile)
		if err != nil {
			fmt.Fprintln(stderr, "port49 revoke:", err)
			return 1
		}
		// The serial goes as explicit hex, 0x after any sign: one of digits
		// alone (sequential CAs issue 10, 11, …) is otherwise taken for a
		// decimal copied by hand, and the report advises against a correct
		// revocation (final review I1).
		req.CertIssuer, req.CertSerial = c.Issuer.String(), hexSerial(c.SerialNumber)
		// The broker's report names the issuer and serial, not whose
		// certificate it is; this says, before anything is sent. Quoted as
		// the broker quotes an issuer: a hostile certificate's names must
		// not reach the terminal as escape sequences.
		fmt.Fprintf(stderr, "port49 revoke: %s: subject %q, issuer %q, serial %s\n", *certFile, c.Subject.String(),
			req.CertIssuer, req.CertSerial)
	}
	return askRevoke(*socket, req, revokeWait, stdout, stderr)
}

// askRevoke sends a revoke or revocations request and prints its answer.
func askRevoke(socket string, req admin.Request, wait time.Duration, stdout, stderr io.Writer) int {
	resp, err := askAdmin(socket, req, wait)
	var unanswered *unansweredError
	if errors.As(err, &unanswered) && req.Op == "revoke" {
		// The request reached port49d, which marks first: the revocation
		// may stand. A retry would only queue behind it.
		what := "revocation"
		if req.Lift {
			what = "lift"
		}
		fmt.Fprintf(stderr, "port49 revoke: port49d did not answer (%v); the %s may be in force — check "+
			"`port49 revoke --list` and port49d's log before retrying\n", unanswered.err, what)
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, "port49 revoke:", err)
		return 1
	}
	if resp.Error != "" {
		fmt.Fprintln(stderr, "port49 revoke:", resp.Error)
		return 1
	}
	fmt.Fprintln(stdout, resp.Text)
	if req.Op == "revocations" {
		fmt.Fprintln(stderr, "port49 revoke: a self or key revocation (--mine, or --via-agent --device) leaves no "+
			"mark and is not listed: port49d's decision log names each (event revoke, revocation.by self or key)")
	}
	if resp.Partial {
		// In force, but not finished or not saved: a script must not read
		// this as done (pre-flight M10).
		return 3
	}
	return 0
}

// revokeOverAgent sends a revocation to the broker through the agent, under
// the caller's api: rights (spec §5.1.4, §12). It prints what the broker
// says it reached and exits as port49 revoke does: 0 done, 1 refused or
// unreachable, 3 in force but incomplete or, for a standing mark, unsaved.
func revokeOverAgent(socket string, req api.RevokeRequest, stdout, stderr io.Writer) int {
	rep, err := agent.NewClient(socket).Revoke(context.Background(), req)
	var refused *agent.APIError
	switch {
	case errors.Is(err, agent.ErrNoAgent):
		fmt.Fprintf(stderr, "port49 revoke: no agent at %s; run 'port49 login'\n", socket)
		return 1
	case errors.As(err, &refused) && refused.Code == "api_right_missing" && req.Principal != "":
		fmt.Fprintln(stderr, "port49 revoke: refused: revoking another principal needs the api: revoke_others "+
			"right, which your subject does not declare")
		return 1
	case errors.As(err, &refused) && refused.Code == "api_right_missing":
		fmt.Fprintf(stderr, "port49 revoke: refused: ending a (device, username) whoever holds it needs the api: "+
			"revoke_others right, which your subject does not declare; for your own session there, use --mine "+
			"--device %s --username %s\n", req.Device, req.Username)
		return 1
	case err != nil:
		// A 503 (revocation_busy among them) carries its code, detail and
		// retry hint in the APIError's text; ErrAgentTooOld says to log in
		// again; a RevokedError says why the session ended.
		fmt.Fprintln(stderr, "port49 revoke:", unprefixed(err))
		return 1
	}
	if rep.By != "self" && rep.Principal != "" {
		// Whom the broker revoked, by the policy's subject, so a misspelt
		// colleague is seen at once (pre-flight M11).
		subject := "no subject in the policy in force names it"
		if rep.Subject != "" {
			subject = "subject " + rep.Subject
		}
		fmt.Fprintf(stdout, "target: %s (%s)\n", rep.Principal, subject)
	}
	fmt.Fprintln(stdout, rep.Text)
	if rep.Incomplete != "" || (rep.Saved != nil && !*rep.Saved) {
		return 3
	}
	return 0
}

// confirmIn and confirmTTY are where port49 revoke --via-agent --principal
// asks before it puts a standing mark on someone from a laptop (pre-flight
// M11): the terminal, and only when stdin is one. Swapped in tests.
var (
	confirmIn  io.Reader = os.Stdin
	confirmTTY           = func() bool { return isTerminal(os.Stdin) }
)

// confirmRevoke asks whether to revoke principal, on stderr, and reads one
// line: y or yes goes on, anything else, an empty line or EOF included,
// does not.
func confirmRevoke(principal string, stderr io.Writer) bool {
	fmt.Fprintf(stderr, "revoke %s everywhere? It is a standing mark: every mint by it is refused until it is "+
		"lifted on port49d's admin socket. [y/N] ", principal)
	line, _ := bufio.NewReader(confirmIn).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

// hexSerial is a serial as the broker reads it, hex with a 0x prefix and
// any minus sign kept in front (Go 1.22 still parses a negative serial).
func hexSerial(n *big.Int) string {
	s := n.Text(16)
	if strings.HasPrefix(s, "-") {
		return "-0x" + s[1:]
	}
	return "0x" + s
}

// readCertificate is the one certificate in a file, PEM or DER. A
// certificate is public; it is read as a plain file. A file that holds a
// private key is refused whole: the key has no business here, and an
// operator who pointed at it should know. A file of more than one
// certificate is refused too: a chain or a bundle in the wrong order would
// revoke the CA's serial and say it did. Nothing of a block is ever printed.
func readCertificate(path string) (*x509.Certificate, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxCertFile+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxCertFile {
		return nil, fmt.Errorf("%s is larger than 1 MiB; a certificate is a few KiB", path)
	}
	var certs [][]byte
	blocks := 0
	for rest := raw; ; {
		var blk *pem.Block
		if blk, rest = pem.Decode(rest); blk == nil {
			break
		}
		blocks++
		if strings.Contains(blk.Type, "PRIVATE KEY") {
			return nil, errors.New(path + " holds a private key; give the certificate alone")
		}
		if blk.Type == "CERTIFICATE" {
			certs = append(certs, blk.Bytes)
		}
	}
	if blocks == 0 {
		// Not PEM: DER, one certificate, or a key in DER.
		if derPrivateKey(raw) {
			return nil, errors.New(path + " holds a private key; give the certificate alone")
		}
		certs = [][]byte{raw}
	}
	switch len(certs) {
	case 0:
		return nil, errors.New(path + " holds no certificate")
	case 1:
	default:
		return nil, fmt.Errorf("%s holds %d certificates; give the leaf alone", path, len(certs))
	}
	c, err := x509.ParseCertificate(certs[0])
	if err != nil {
		if blocks == 0 {
			return nil, errors.New(path + " holds no certificate, PEM or DER")
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// derPrivateKey is whether raw parses as a private key in DER.
func derPrivateKey(raw []byte) bool {
	if _, err := x509.ParsePKCS8PrivateKey(raw); err == nil {
		return true
	}
	if _, err := x509.ParsePKCS1PrivateKey(raw); err == nil {
		return true
	}
	_, err := x509.ParseECPrivateKey(raw)
	return err == nil
}

// unansweredError is askAdmin's failure after the request was written: the
// op may have run.
type unansweredError struct{ err error }

func (e *unansweredError) Error() string { return e.err.Error() }
func (e *unansweredError) Unwrap() error { return e.err }

// askAdmin sends req to port49d's admin socket and returns its one answer,
// waiting at most wait. The socket answers port49d's user and root alone.
// The write side stays open until the answer is read: port49d takes a
// half-close for a hang-up and abandons the op. A failure once the request
// is written is an *unansweredError.
func askAdmin(socket string, req admin.Request, wait time.Duration) (admin.Response, error) {
	c, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return admin.Response{}, fmt.Errorf("%v (is admin_socket set in port49d.yaml, and are you port49d's user "+
			"or root?)", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(wait))
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return admin.Response{}, err
	}
	var resp admin.Response
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return admin.Response{}, &unansweredError{err}
	}
	return resp, nil
}
