//go:build lab

package lab

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// l53Shown recognises the key in a console command's output: its OpenSSH
// base64 blob, its SHA256 fingerprint, its DER as hex (IOS-XE's `show crypto
// key mypubkey rsa`), its MD5 fingerprint, or none of them.
func TestL53ShownReadsEachForm(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	blob := base64.StdEncoding.EncodeToString(k.Marshal())
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := ssh.NewPublicKey(&rk.PublicKey)
	spki, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	var grouped strings.Builder // IOS-XE's form: upper-case hex, 8 digits a group, 8 groups a line
	for i, c := range strings.ToUpper(hex.EncodeToString(spki)) {
		if i > 0 && i%8 == 0 {
			grouped.WriteString(map[bool]string{true: "\n  ", false: " "}[i%64 == 0])
		}
		grouped.WriteRune(c)
	}
	md5 := ssh.FingerprintLegacyMD5(r)
	for _, c := range []struct {
		out  string
		k    ssh.PublicKey
		want string
	}{
		{"ssh-ed25519 " + blob + " root@leaf1\n", k, "base64 key"},
		{"Fingerprint: " + ssh.FingerprintSHA256(k) + "\n", k, "SHA256 fingerprint"},
		{"ssh-ed25519 " + blob[:20] + "\n" + blob[20:] + "\n", k, "base64 key"},
		{"Key name: leaf1.lab\n Key Data:\n  " + grouped.String() + "\n", r, "hex DER key"},
		{"bitcount:2048 fingerprint:\n" + md5 + "\n", r, "MD5 fingerprint"},
		{"fingerprint " + strings.ToUpper(strings.ReplaceAll(md5, ":", "")) + "\n", r, "MD5 fingerprint"},
		{"RSA key fingerprint is 9b:2a:..., other key\n", k, ""},
		{strings.Repeat("x", 100), k, ""},
		{"Key Data:\n  " + grouped.String() + "\n", k, ""},
	} {
		if got := l53Shown(c.out, c.k); got != c.want {
			t.Errorf("l53Shown(%q) = %q, want %q", c.out, got, c.want)
		}
	}
}
