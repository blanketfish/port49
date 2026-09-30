//go:build linux

package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// withAdminSocket adds admin_socket to the config at cfgPath.
func withAdminSocket(t *testing.T, cfgPath, socket string) {
	t.Helper()
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, append([]byte("admin_socket: "+socket+"\n"), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
}

// An admin_socket port49d cannot open ends the start, says nothing is
// listening, and lets go of the broker's port (pre-flight M6).
func TestRunWithAnAdminSocketItCannotOpenReleasesTheBroker(t *testing.T) {
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	brokerAddr := free.Addr().String()
	free.Close()
	b := brokerConfig(t, minimalPolicy).Broker
	b.Listen = brokerAddr
	cfgPath := writeRunConfig(t, b)
	socket := filepath.Join(filepath.Dir(cfgPath), "port49d.sock")
	if err := os.WriteFile(socket, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	withAdminSocket(t, cfgPath, socket)
	out, err := runExpectingRefusal(t, cfgPath)
	if err == nil || !strings.Contains(err.Error(), "admin_socket "+socket) || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(out, "listening") {
		t.Fatalf("stderr claims a listener is up: %q", out)
	}
	again, err := net.Listen("tcp", brokerAddr)
	if err != nil {
		t.Fatalf("the broker's port is still held: %v", err)
	}
	again.Close()
}

// With admin_socket set, a packet under a key port49d does not hold is held
// for the device, and keys_diagnose over the socket names what it validates
// under, and the group the policy in force assigns.
func TestRunAnswersKeysDiagnoseOverTheAdminSocket(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log

	b := brokerConfig(t, minimalPolicy).Broker
	cfgPath := writeRunConfig(t, b)
	socket := filepath.Join(filepath.Dir(cfgPath), "port49d.sock")
	withAdminSocket(t, cfgPath, socket)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})
	waitFor(t, &out, "port49d: broker listening on ")
	waitFor(t, &out, "port49d: admin socket on "+socket)
	addr := regexp.MustCompile(`port49d: listening on (127\.0\.0\.1:\d+)`).FindStringSubmatch(out.String())
	if addr == nil {
		t.Fatalf("stderr: %q", out.String())
	}
	if fi, err := os.Lstat(socket); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v, %v", fi, err)
	}

	ask := func() admin.Response {
		t.Helper()
		c, err := net.Dial("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		json.NewEncoder(c).Encode(admin.Request{Op: "keys_diagnose", Device: "leaf1"})
		var r admin.Response
		if err := json.NewDecoder(c).Decode(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := ask(); !strings.Contains(r.Error, "holds no unvalidated packet") {
		t.Fatalf("%+v", r)
	}

	conn, err := net.Dial("tcp", addr[1])
	if err != nil {
		t.Fatal(err)
	}
	body := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("pw-never-returned")}.Encode()
	h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, SessionID: 0x5eed, Length: uint32(len(body))}
	conn.Write(append(h.Encode(), wire.Obfuscate(h, []byte("a-key-port49d-lacks"), body)...))
	defer conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	r := ask()
	for r.Error != "" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		r = ask()
	}
	if r.Finding == nil || len(r.Finding.Matches) != 0 || r.Finding.Assigned != "k" ||
		!strings.Contains(r.Text, "validates under nothing port49d holds") {
		t.Fatalf("%+v", r)
	}
	raw, _ := json.Marshal(r)
	for _, leak := range []string{"pw-never-returned", "run-test-secret", "a-key-port49d-lacks"} {
		if strings.Contains(string(raw), leak) || strings.Contains(log.String(), leak) {
			t.Fatalf("%q reached the answer or the log", leak)
		}
	}
}
