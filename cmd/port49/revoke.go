package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

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
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
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
		req.CertIssuer, req.CertSerial = c.Issuer.String(), c.SerialNumber.Text(16)
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
	if resp.Partial {
		// In force, but not finished or not saved: a script must not read
		// this as done (pre-flight M10).
		return 3
	}
	return 0
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
