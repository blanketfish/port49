package decision

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEmitWritesOneLinePerRecord(t *testing.T) {
	var buf bytes.Buffer
	e := NewJSONLines(&buf)
	ts := time.Date(2026, 9, 4, 2, 11, 7, 412_000_000, time.UTC)
	e.Emit(Record{TS: ts, Event: EventRedeem, Verdict: VerdictPermit, Reason: TokenRedeemed,
		Principal: "user:alice@example.com",
		Auth:      &Auth{Method: "pap", CredentialSHA256: CredentialHash([]byte("tok"))},
		Device:    &Device{NAS: "10.20.0.7", Name: "leaf-01", Platform: "arista_eos"},
		Session:   &Session{CtxID: "01J", Port: "vty0", RemAddr: "198.51.100.4", Privilege: 1}})
	e.Emit(Record{TS: ts, Event: EventAccount, Flags: "stop", Attribution: "unattributed"})

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines: %q", buf.String())
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatal(err)
	}
	if m["ts"] != "2026-09-04T02:11:07.412Z" || m["event"] != "redeem" || m["reason"] != "token_redeemed" {
		t.Fatalf("%v", m)
	}
	if strings.Contains(lines[0], "tok\"") {
		t.Fatal("credential leaked into the log")
	}
	for k := range m {
		if strings.ToLower(k) != k || strings.Contains(k, "-") {
			t.Fatalf("key %q is not snake_case", k)
		}
	}
}

func TestCredentialHashIsHexSHA256(t *testing.T) {
	h := CredentialHash([]byte("abc"))
	if h != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("%s", h)
	}
}
