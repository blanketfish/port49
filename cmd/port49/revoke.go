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

// revokeWait is how long `port49 revoke` waits for port49d's answer: a
// revoke may wait its turn (admin.OpTimeout) and then run under its own bound
// of the same length, and port49d holds the connection open for both, so
// the client does too. Hanging up sooner would lose the report of a
// revocation that finishes anyway.
const revokeWait = 2*admin.OpTimeout + 10*time.Second

// revokeCmd is `port49 revoke` (spec §12; plan 7a): it asks port49d, over
// its admin socket, to revoke or lift a principal or one certificate, or to
// list the revocations in force.
func revokeCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", "/run/port49/port49d.sock", "port49d's admin_socket")
	principal := fs.String("principal", "", "the principal, as the log names it: user:alice@example.com")
	certFile := fs.String("cert", "", "a PEM file holding the certificate; its issuer and serial are read from it")
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
	req := admin.Request{Op: "revoke", Principal: *principal, CertIssuer: *issuer, CertSerial: *serial, Lift: *lift}
	if *certFile != "" {
		if *issuer != "" || *serial != "" {
			fmt.Fprintln(stderr, "port49 revoke: --cert, or --cert-issuer and --cert-serial; not both")
			return 2
		}
		c, err := readCertificate(*certFile)
		if err != nil {
			fmt.Fprintln(stderr, "port49 revoke:", err)
			return 1
		}
		req.CertIssuer, req.CertSerial = c.Issuer.String(), c.SerialNumber.Text(16)
	}
	byCert := req.CertIssuer != "" || req.CertSerial != ""
	switch {
	case *list:
		if *principal != "" || byCert || *lift {
			fmt.Fprintln(stderr, "port49 revoke: --list takes no principal, certificate or --lift")
			return 2
		}
		req = admin.Request{Op: "revocations"}
	case (*principal != "") == byCert:
		fmt.Fprintln(stderr, "port49 revoke: name a principal (--principal), or a certificate (--cert, or "+
			"--cert-issuer and --cert-serial); one of the two")
		return 2
	case byCert && (req.CertIssuer == "" || req.CertSerial == ""):
		fmt.Fprintln(stderr, "port49 revoke: a certificate is named by --cert-issuer and --cert-serial, both")
		return 2
	}
	resp, err := askAdmin(*socket, req, revokeWait)
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

// readCertificate is the first certificate in a PEM file. A certificate is
// public; it is read as a plain file. A file that also holds a private key
// is refused whole: the key has no business here, and an operator who
// pointed at it should know. Nothing of a block is ever printed.
func readCertificate(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cert []byte
	for rest := raw; ; {
		var blk *pem.Block
		if blk, rest = pem.Decode(rest); blk == nil {
			break
		}
		if strings.Contains(blk.Type, "PRIVATE KEY") {
			return nil, errors.New(path + " holds a private key; give the certificate alone")
		}
		if blk.Type == "CERTIFICATE" && cert == nil {
			cert = blk.Bytes
		}
	}
	if cert == nil {
		return nil, errors.New(path + " holds no PEM certificate")
	}
	c, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// askAdmin sends req to port49d's admin socket and returns its one answer,
// waiting at most wait. The socket answers port49d's user and root alone.
// The write side stays open until the answer is read: port49d takes a
// half-close for a hang-up and abandons the op.
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
		return admin.Response{}, err
	}
	return resp, nil
}
