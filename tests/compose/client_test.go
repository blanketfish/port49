//go:build compose

package compose

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
)

// device is the smallest TACACS+ client that logs in and asks for
// authorization, one exchange per connection, as port49d's own tests'
// tacacsClient (internal/port49d/run_test.go), which this package cannot
// import.
type device struct {
	t    *testing.T
	addr string
	key  []byte
}

func (d device) exchange(typ wire.Type, body []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", d.addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	h := wire.Header{MajorVersion: 0xc, Type: typ, SeqNo: 1, SessionID: 0x5eed, Length: uint32(len(body))}
	if _, err := conn.Write(append(h.Encode(), wire.Obfuscate(h, d.key, body)...)); err != nil {
		return nil, err
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	hb := make([]byte, wire.HeaderLen)
	if _, err := io.ReadFull(conn, hb); err != nil {
		return nil, err
	}
	rh, _ := wire.DecodeHeader(hb)
	rb := make([]byte, rh.Length)
	if _, err := io.ReadFull(conn, rb); err != nil {
		return nil, err
	}
	return wire.Obfuscate(rh, d.key, rb), nil
}

// login is a PAP login; it fails the test on a connection that was not
// answered: port49d resets a source it does not admit (design §12).
func (d device) login(user, password string) uint8 {
	d.t.Helper()
	b, err := d.exchange(wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte(user), Port: []byte("ssh"),
		RemAddr: []byte("198.51.100.4"), Data: []byte(password)}.Encode())
	if err != nil {
		d.t.Fatalf("login: %v (a reset is port49d not admitting the source it saw: the inventory names "+
			"172.30.49.1, the stack's gateway; read `docker compose logs port49d`)", err)
	}
	r, err := wire.DecodeAuthenReply(b)
	if err != nil {
		d.t.Fatal(err)
	}
	return r.Status
}

// permits asks for user's session (no words) or a command at 15.
func (d device) permits(user string, words ...string) bool {
	d.t.Helper()
	priv := uint8(15)
	args := [][]byte{[]byte("service=shell")}
	if len(words) == 0 {
		args, priv = append(args, []byte("cmd=")), 1
	} else {
		args = append(args, []byte("cmd="+words[0]))
		for _, w := range words[1:] {
			args = append(args, []byte("cmd-arg="+w))
		}
		args = append(args, []byte("cmd-arg=<cr>"))
	}
	b, err := d.exchange(wire.TypeAuthor, wire.AuthorRequest{AuthenMethod: wire.AuthenMethodTACACSPlus,
		PrivLvl: priv, AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin, User: []byte(user),
		Port: []byte("vty1"), Args: args}.Encode())
	if err != nil {
		d.t.Fatalf("authorize: %v", err)
	}
	r, err := wire.DecodeAuthorResponse(b)
	if err != nil {
		d.t.Fatal(err)
	}
	return r.Status == wire.AuthorStatusPassAdd || r.Status == wire.AuthorStatusPassRepl
}

// mint asks the broker at addr for a token on device with the client
// certificate WriteCompose cut for alice. The answer carries a token and
// is never printed. A 503 is tried again for up to 60s, as port49 workload
// retries it: a first start's broker holds every mint until its takeover
// judges the bundle (decision 36, the start gate).
func mint(t *testing.T, local, addr, device string) string {
	t.Helper()
	pki := filepath.Join(local, "broker")
	cert, err := tls.LoadX509KeyPair(filepath.Join(pki, testpki.LabClientCert), filepath.Join(pki, testpki.LabClientKey))
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(filepath.Join(pki, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{cert}, RootCAs: roots, MinVersion: tls.VersionTLS13}}}
	var resp *http.Response
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(time.Second) {
		resp, err = c.Post("https://"+addr+"/v1/tokens", "application/json",
			bytes.NewReader([]byte(`{"devices":["`+device+`"]}`)))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusServiceUnavailable || time.Now().After(deadline) {
			break
		}
		resp.Body.Close()
		t.Logf("mint: 503, the broker's start gate; trying again")
	}
	defer resp.Body.Close()
	var out api.MintResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("mint: status %d, the body does not decode", resp.StatusCode)
	}
	if len(out.Results) != 1 || out.Results[0].Login == "" {
		// MintItem.String withholds tokens (internal/broker/api/api.go:57), so
		// %v names the refusal and prints no credential.
		t.Fatalf("mint: status %d, %d result(s): %v", resp.StatusCode, len(out.Results), out.Results)
	}
	return out.Results[0].Login
}
