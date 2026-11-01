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
	"net/http"
	"os"
	"strings"

	"github.com/blanketfish/port49/internal/agent"
	"github.com/blanketfish/port49/internal/broker/api"
)

// maxCertFile bounds the --cert file read: a certificate is a few KiB, and
// a mistyped path (/dev/zero, a log) must not hang or exhaust the client.
const maxCertFile = 1 << 20

// revokeCmd is `port49 revoke` (spec §5.1.4, §5.1.6, §12): it asks the broker,
// through your agent and under your api: rights, to revoke or lift a principal,
// a certificate or a key, or to list the revocations in force. Every write but
// --mine needs a press of your security key, bound to that one request.
func revokeCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	principal := fs.String("principal", "", "the principal, as the log names it: user:alice@example.com")
	certFile := fs.String("cert", "", "a file holding the one certificate (PEM or DER); its issuer and serial are read from it")
	issuer := fs.String("cert-issuer", "", "the certificate's issuer, as the broker spells it (RFC 2253: CN=…,O=…)")
	serial := fs.String("cert-serial", "", "the certificate's serial, in hex")
	lift := fs.Bool("lift", false, "lift the revocation instead")
	list := fs.Bool("list", false, "list the revocations in force")
	mine := fs.Bool("mine", false, "end your own sessions and delete your own unspent tokens; leaves no mark, asks for no touch")
	device := fs.String("device", "", "one device, by its inventory name, with --username (and --mine for your own session there)")
	username := fs.String("username", "", "with --device: the device-facing username")
	sid := fs.String("sid", "", "end one OIDC session by its sid, as a back-channel logout does; with --sid-issuer")
	sidIssuer := fs.String("sid-issuer", "", "with --sid: the provider's issuer URL, as the broker's log names it")
	yes := fs.Bool("yes", false, "with --principal: do not ask before revoking")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	byCert := *certFile != "" || *issuer != "" || *serial != ""
	byKey := *device != "" || *username != ""
	bySid := *sid != "" || *sidIssuer != ""
	switch {
	case *yes && (*principal == "" || *lift || *list || *mine):
		fmt.Fprintln(stderr, "port49 revoke: --yes goes with --principal, the one form that asks")
		return 2
	case bySid && (*sid == "" || *sidIssuer == ""):
		fmt.Fprintln(stderr, "port49 revoke: a session is named by --sid and --sid-issuer, both")
		return 2
	case bySid && (*principal != "" || byCert || byKey || *lift || *mine || *list):
		fmt.Fprintln(stderr, "port49 revoke: --sid names one session; it takes no principal, certificate, key, "+
			"--lift, --list or --mine")
		return 2
	case *list && (*principal != "" || byCert || byKey || *lift || *mine):
		fmt.Fprintln(stderr, "port49 revoke: --list takes no principal, certificate, key, --lift or --mine")
		return 2
	case *mine && (*principal != "" || byCert || *lift):
		fmt.Fprintln(stderr, "port49 revoke: --mine names yourself (with --device and --username, your own session "+
			"there); use --principal, --cert, or --device and --username alone for another")
		return 2
	case byKey && (*device == "") != (*username == ""):
		fmt.Fprintln(stderr, "port49 revoke: --device and --username go together")
		return 2
	case *certFile != "" && (*issuer != "" || *serial != ""):
		fmt.Fprintln(stderr, "port49 revoke: --cert, or --cert-issuer and --cert-serial; not both")
		return 2
	case byCert && *certFile == "" && (*issuer == "" || *serial == ""):
		fmt.Fprintln(stderr, "port49 revoke: a certificate is named by --cert-issuer and --cert-serial, both")
		return 2
	case byKey && *lift:
		fmt.Fprintln(stderr, "port49 revoke: --lift names a principal or a certificate; a key (a session) has no mark to lift")
		return 2
	}
	if *mine {
		return revokeMine(api.RevokeRequest{Mine: true, Device: *device, Username: *username}, stdout, stderr)
	}
	if *list {
		return revokeList(stdout, stderr)
	}
	forms := 0
	for _, set := range []bool{*principal != "", byCert, byKey, bySid} {
		if set {
			forms++
		}
	}
	if forms != 1 {
		fmt.Fprintln(stderr, "port49 revoke: name a principal (--principal), a certificate (--cert, or "+
			"--cert-issuer and --cert-serial), a key (--device and --username), or a session (--sid and --sid-issuer); one of the four. Your own "+
			"sessions are --mine")
		return 2
	}
	var rev api.RevokeRequest
	switch {
	case bySid:
		rev = api.RevokeRequest{Sid: *sid, Issuer: *sidIssuer}
	case byKey:
		rev = api.RevokeRequest{Device: *device, Username: *username}
	case byCert:
		rev = api.RevokeRequest{CertIssuer: *issuer, CertSerial: *serial}
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
			rev.CertIssuer, rev.CertSerial = c.Issuer.String(), hexSerial(c.SerialNumber)
			// The broker's report names the issuer and serial, not whose
			// certificate it is; this says, before anything is sent. Quoted as
			// the broker quotes an issuer: a hostile certificate's names must
			// not reach the terminal as escape sequences.
			fmt.Fprintf(stderr, "port49 revoke: %s: subject %q, issuer %q, serial %s\n", *certFile, c.Subject.String(),
				rev.CertIssuer, rev.CertSerial)
		}
	default:
		rev = api.RevokeRequest{Principal: *principal}
	}
	if *lift {
		l := api.LiftRequest{Principal: rev.Principal, CertIssuer: rev.CertIssuer, CertSerial: rev.CertSerial}
		return revokeAdmin("lift", "/v1/revocations/lift", l, stdout, stderr)
	}
	if *principal != "" && !*yes && confirmTTY() && !confirmRevoke(*principal, stderr) {
		fmt.Fprintln(stderr, "port49 revoke: nothing was revoked")
		return 1
	}
	return revokeAdmin("revocation", "/v1/tokens/revoke", rev, stdout, stderr)
}

// revokeAdmin makes one revoke or lift call through the agent and prints its
// answer; what is the word an unanswered call is named by.
func revokeAdmin(what, path string, in any, stdout, stderr io.Writer) int {
	body, err := json.Marshal(in)
	if err != nil {
		fmt.Fprintln(stderr, "port49 revoke:", err)
		return 1
	}
	resp, code := adminCall("port49 revoke", agent.AdminRequest{Method: http.MethodPost, Path: path, Body: body},
		fmt.Sprintf("the %s may be in force: check `port49 revoke --list` and the broker's decision log (event "+
			"revoke) before trying again", what), stderr)
	if code != 0 {
		return code
	}
	if path == "/v1/revocations/lift" {
		return printAdminResult("port49 revoke", resp, stdout, stderr)
	}
	var rep api.RevokeResponse
	if json.Unmarshal(resp.Body, &rep) != nil || rep.By == "" {
		fmt.Fprintln(stderr, "port49 revoke: the broker's answer named no revocation; it may be in force: check "+
			"`port49 revoke --list` and the broker's decision log before trying again")
		return 1
	}
	printRevokeReport(rep, stdout)
	if rep.Incomplete != "" || (rep.Saved != nil && !*rep.Saved) {
		return 3
	}
	return 0
}

// revokeList prints the revocations in force: a read under revoke_others or
// lift_revocations, with no touch.
func revokeList(stdout, stderr io.Writer) int {
	resp, code := adminCall("port49 revoke", agent.AdminRequest{Method: http.MethodGet, Path: "/v1/revocations"}, "", stderr)
	if code != 0 {
		return code
	}
	var list api.RevocationList
	if json.Unmarshal(resp.Body, &list) != nil {
		fmt.Fprintln(stderr, "port49 revoke: the broker's answer is not a revocation list; run it again, and look at "+
			"the broker's log if it does it again")
		return 1
	}
	fmt.Fprintln(stdout, safeText(list.Text))
	fmt.Fprintln(stderr, "port49 revoke: a self or key revocation (--mine, or --device and --username) leaves no mark "+
		"and is not listed: the broker's decision log names each (event revoke, revocation.by self or key)")
	return 0
}

// revokeMine ends the caller's own sessions through the agent: no mark, no
// touch (spec §5.1.4). It exits as port49 revoke does: 0 done, 1 refused or
// unreachable, 3 incomplete.
func revokeMine(req api.RevokeRequest, stdout, stderr io.Writer) int {
	rep, err := agent.NewClient(agent.SocketPath()).Revoke(context.Background(), req)
	var refused *agent.APIError
	switch {
	case errors.Is(err, agent.ErrNoAgent):
		fmt.Fprintln(stderr, "port49 revoke: no agent is running for you; run 'port49 login', then run this again")
		return 1
	case errors.As(err, &refused):
		fmt.Fprintf(stderr, "port49 revoke: refused: %s: %s\n", safeLine(refused.Code), safeLine(refused.Detail))
		return 1
	case err != nil:
		// A 503 (revocation_busy among them) carries its code, detail and
		// retry hint in the APIError's text; ErrAgentTooOld says to log in
		// again; a RevokedError says why the session ended.
		fmt.Fprintln(stderr, "port49 revoke:", safeLine(unprefixed(err)))
		return 1
	}
	printRevokeReport(rep, stdout)
	if rep.Incomplete != "" || (rep.Saved != nil && !*rep.Saved) {
		return 3
	}
	return 0
}

// printRevokeReport prints what the broker says it reached.
func printRevokeReport(rep api.RevokeResponse, stdout io.Writer) {
	if rep.By != "self" && rep.Principal != "" {
		// Whom the broker revoked, by the policy's subject, so a misspelt
		// colleague is seen at once (pre-flight M11).
		subject := "no subject in the policy in force names it"
		if rep.Subject != "" {
			subject = "subject " + safeLine(rep.Subject)
		}
		fmt.Fprintf(stdout, "target: %s (%s)\n", safeLine(rep.Principal), subject)
	}
	fmt.Fprintln(stdout, safeText(rep.Text))
}

// confirmIn and confirmTTY are where port49 revoke --principal asks before it
// puts a standing mark on someone from a laptop (pre-flight M11): the
// terminal, and only when stdin is one. Swapped in tests.
var (
	confirmIn  io.Reader = os.Stdin
	confirmTTY           = func() bool { return isTerminal(os.Stdin) }
)

// confirmRevoke asks whether to revoke principal, on stderr, and reads one
// line: y or yes goes on, anything else, an empty line or EOF included,
// does not.
func confirmRevoke(principal string, stderr io.Writer) bool {
	fmt.Fprintf(stderr, "revoke %s everywhere? It is a standing mark: every mint by it is refused until it is "+
		"lifted with port49 revoke --lift. [y/N] ", principal)
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
