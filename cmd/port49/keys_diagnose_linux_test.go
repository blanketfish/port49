//go:build linux

package main

import (
	"bytes"
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/keyring"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// keys diagnose asks port49d over its admin socket and prints the one line
// port49d answers; a device with nothing held, or no socket, is exit 1.
func TestKeysDiagnoseAsksTheAdminSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "port49d.sock")
	ln, err := admin.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	held := &keyring.Held{}
	h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, SessionID: 7}
	body := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("u"), Data: []byte("pw-never-printed")}.Encode()
	h.Length = uint32(len(body))
	held.Put("leaf-19", netip.MustParseAddr("10.20.4.9"), h, wire.Obfuscate(h, []byte("S3CR3T-OLD"), body), now.Add(-time.Minute))
	srv := &admin.Server{Held: held, Now: func() time.Time { return now },
		Keys: map[string]keyring.Set{"prod_key": {Ref: "prod_key", Versions: []keyring.Version{
			{Number: 3, Secret: []byte("S3CR3T-NEW")}, {Number: 2, Secret: []byte("S3CR3T-OLD"), Retired: true}}}},
		Assigned: func(string) string { return "prod_key" }}
	go srv.Serve(ctx, ln)

	var out, errb bytes.Buffer
	if code := run([]string{"keys", "diagnose", "--socket", socket, "leaf-19"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if s := out.String(); !strings.Contains(s, "leaf-19 (10.20.4.9), packet held 1m0s ago: validates under prod_key v2 (retired)") ||
		!strings.Contains(s, "missed in the rotation") || strings.Contains(s, "S3CR3T") || strings.Contains(s, "pw-never-printed") {
		t.Fatalf("%q", s)
	}

	out.Reset()
	errb.Reset()
	if code := run([]string{"keys", "diagnose", "--socket", socket, "spine-02"}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "holds no unvalidated packet") {
		t.Fatalf("exit %d: %q", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"keys", "diagnose", "--socket", socket + ".missing", "leaf-19"}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "is admin_socket set") {
		t.Fatalf("exit %d: %q", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"keys", "diagnose", "--socket", socket}, &out, &errb); code != 2 {
		t.Fatalf("no device: exit %d", code)
	}
}
