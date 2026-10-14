// Command standin is L66 (e)'s stand-in host: an SSH server on the lab bridge with its own host keys
// (Ed25519, ECDSA P-256 and RSA 2048, generated at start) that refuses every login and says what it was
// offered. It stands in for "another host at the address a device's name used to have": whether an Ansible
// connection presents the device's token to it is the measurement.
//
// It logs one JSON object per line on stdout. A password or a keyboard-interactive answer is logged as its
// length and its SHA-256, never its text, so the log can be read, kept and compared with the decision log's
// credential_sha256 without holding a credential.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"
)

var (
	outMu sync.Mutex
	out   = json.NewEncoder(os.Stdout)
)

// say writes one event. The fields are outcomes, counts, a hash and a key type; nothing in them is a
// credential.
func say(v map[string]any) {
	outMu.Lock()
	defer outMu.Unlock()
	_ = out.Encode(v)
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hostSigners() ([]ssh.Signer, error) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	var signers []ssh.Signer
	for _, k := range []any{ed, ec, rk} {
		s, err := ssh.NewSignerFromKey(k)
		if err != nil {
			return nil, err
		}
		signers = append(signers, s)
	}
	return signers, nil
}

func main() {
	listen := flag.String("listen", ":22", "address to listen on")
	flag.Parse()

	signers, err := hostSigners()
	if err != nil {
		fmt.Fprintln(os.Stderr, "standin:", err)
		os.Exit(1)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			say(map[string]any{"event": "password_attempt", "user": c.User(), "remote": c.RemoteAddr().String(),
				"len": len(pw), "sha256": sum(pw)})
			return nil, errors.New("refused")
		},
		KeyboardInteractiveCallback: func(c ssh.ConnMetadata, ask ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := ask(c.User(), "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			for _, a := range answers {
				say(map[string]any{"event": "kbdint_attempt", "user": c.User(), "remote": c.RemoteAddr().String(),
					"len": len(a), "sha256": sum([]byte(a))})
			}
			return nil, errors.New("refused")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			say(map[string]any{"event": "publickey_offered", "user": c.User(), "key_type": k.Type()})
			return nil, errors.New("refused")
		},
	}
	var prints []string
	for _, s := range signers {
		cfg.AddHostKey(s)
		prints = append(prints, s.PublicKey().Type()+" "+ssh.FingerprintSHA256(s.PublicKey()))
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "standin:", err)
		os.Exit(1)
	}
	say(map[string]any{"event": "ready", "listen": ln.Addr().String(), "host_keys": prints})
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, "standin:", err)
			os.Exit(1)
		}
		go func() {
			defer conn.Close()
			say(map[string]any{"event": "connect", "remote": conn.RemoteAddr().String()})
			sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
			if err != nil {
				say(map[string]any{"event": "ended", "remote": conn.RemoteAddr().String(), "error": err.Error()})
				return
			}
			// Nothing logs in; if something somehow did, it is closed at once.
			go ssh.DiscardRequests(reqs)
			go func() {
				for c := range chans {
					_ = c.Reject(ssh.Prohibited, "no")
				}
			}()
			say(map[string]any{"event": "login_succeeded", "user": sc.User()})
			sc.Close()
		}()
	}
}
