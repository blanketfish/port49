package decision

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestEmitWritesOneLinePerRecord(t *testing.T) {
	var buf bytes.Buffer
	e := NewJSONLines(&buf)
	ts := time.Date(2026, 9, 4, 2, 11, 7, 412_000_000, time.UTC)
	e.Emit(Record{TS: ts, Event: EventRedeem, Verdict: VerdictPermit, Reason: TokenRedeemed,
		Principal:   "user:alice@example.com",
		Auth:        &Auth{Method: "pap", CredentialSHA256: CredentialHash([]byte("tok"))},
		Device:      &Device{NAS: "10.20.0.7", Name: "leaf-01", Platform: "arista_eos"},
		Session:     &Session{CtxID: "01J", Port: "vty0", RemAddr: "198.51.100.4", Privilege: 1},
		Request:     &Request{Raw: []string{"user"}, Vector: []string{"tacacs"}},
		AcctRecord:  &AcctRecord{Raw: []string{"start"}, Vector: []string{"tacacs"}, PrivLvl: 15},
		Unvalidated: &Unvalidated{Source: "10.0.0.1", Diagnosis: "unknown_key", Type: 0xc0, SeqNo: 1, SessionID: 123, Length: 100, BodySHA256: "abc123"}})
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
	assertSnakeCase(t, "", m)
}

func assertSnakeCase(t *testing.T, path string, v any) {
	switch v := v.(type) {
	case map[string]any:
		for k, val := range v {
			if strings.ToLower(k) != k || strings.Contains(k, "-") {
				t.Fatalf("key %q is not snake_case", path+"."+k)
			}
			assertSnakeCase(t, path+"."+k, val)
		}
	case []any:
		for i, val := range v {
			assertSnakeCase(t, path+"["+string(rune(i))+"]", val)
		}
	}
}

func TestRecordJSONRoundTrips(t *testing.T) {
	ts := time.Date(2026, 9, 4, 2, 11, 7, 412_000_000, time.UTC)
	want := Record{TS: ts, Event: EventAccount, Flags: "stop", Attribution: "resolved", TaskID: "43",
		Principal: "user:alice@example.com",
		Device:    &Device{NAS: "10.20.0.7", Name: "leaf-01", Platform: "arista_eos"},
		Session:   &Session{CtxID: "ctx1", Port: "vty0", RemAddr: "198.51.100.4", Privilege: 15},
		AcctRecord: &AcctRecord{Raw: []string{"task_id=43", "cmd=show"}, Vector: []string{"show"},
			PrivLvl: 15, StartTime: 1757041502, StopTime: 1757041502}}

	b, err := want.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var got Record
	if err := got.UnmarshalJSON(b); err != nil {
		t.Fatal(err)
	}
	if !got.TS.Equal(want.TS) {
		t.Fatalf("ts: got %v want %v", got.TS, want.TS)
	}
	got.TS, want.TS = time.Time{}, time.Time{}
	gotB, _ := json.Marshal(got)
	wantB, _ := json.Marshal(want)
	if string(gotB) != string(wantB) {
		t.Fatalf("round trip mismatch:\ngot  %s\nwant %s", gotB, wantB)
	}
}

func TestCredentialHashIsHexSHA256(t *testing.T) {
	h := CredentialHash([]byte("abc"))
	if h != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("%s", h)
	}
}

// failingWriter refuses every write, standing in for a full disk or a closed
// pipe under the decision log.
type failingWriter struct{ err error }

func (f failingWriter) Write([]byte) (int, error) { return 0, f.err }

// TestWriteFailureIsCounted covers design §11's rule that nothing fails
// silently. A refused decision record is a record that does not exist, while
// the device was still answered: the log is short and, without a counter,
// nothing anywhere says so.
func TestWriteFailureIsCounted(t *testing.T) {
	var failures int
	e := NewJSONLinesWithFailureHook(failingWriter{err: errors.New("write: no space left on device")}, func() { failures++ })
	e.Emit(Record{Event: EventAccount})
	e.Emit(Record{Event: EventAccount})
	if failures != 2 {
		t.Fatalf("want one count per refused record, got %d", failures)
	}
}

// TestNoFailureHookIsFine keeps the hook optional: NewJSONLines is used all
// over the tests and must not require one.
func TestNoFailureHookIsFine(t *testing.T) {
	NewJSONLines(failingWriter{err: errors.New("closed")}).Emit(Record{Event: EventAccount})
}

func TestAnInventoryChangeRecordEncodes(t *testing.T) {
	var buf bytes.Buffer
	NewJSONLines(&buf).Emit(Record{TS: time.Unix(0, 0), Event: EventInventoryChange,
		Device: &Device{Name: "leaf-01", Platform: "arista_eos"},
		Change: &Change{Kind: "address_added", Address: "10.66.0.1", FromBundle: "sha256:a", ToBundle: "sha256:b"}})
	got := buf.String()
	for _, want := range []string{`"event":"inventory_change"`, `"kind":"address_added"`, `"address":"10.66.0.1"`,
		`"from_bundle":"sha256:a"`, `"to_bundle":"sha256:b"`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
	if strings.Contains(got, "key_ref") {
		t.Errorf("a record no key validated names no key: %s", got)
	}
}

// policy.subjects replaces policy.subject when several matched, and
// auth.directory names where the membership came from and never a group
// (spec §5.7; decision 38).
func TestSubjectsAndDirectoryShapes(t *testing.T) {
	var b bytes.Buffer
	l := NewJSONLines(&b)
	l.Emit(Record{TS: time.Unix(1_000_000, 0), Event: EventMint, Verdict: VerdictPermit, Reason: GrantsMatched,
		Principal: "user:alice@corp.example.com",
		Auth: &Auth{Method: "cert", Directory: &Directory{Source: "grace", VerifiedAt: "1970-01-12T13:46:40Z",
			Server: "ldaps://dc-01", Site: "us-west"}},
		Policy: &Policy{Bundle: "sha256:b", Subjects: []string{"netops_oncall", "netops_ro"}}})
	var m map[string]any
	if err := json.Unmarshal(b.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	p := m["policy"].(map[string]any)
	if _, ok := p["subject"]; ok || len(p["subjects"].([]any)) != 2 {
		t.Fatalf("policy %v", p)
	}
	d := m["auth"].(map[string]any)["directory"].(map[string]any)
	if d["source"] != "grace" || d["verified_at"] != "1970-01-12T13:46:40Z" || d["server"] != "ldaps://dc-01" {
		t.Fatalf("auth.directory %v", d)
	}
	if strings.Contains(b.String(), "group") {
		t.Fatalf("a record names no group: %s", b.String())
	}
}

func TestAuthCarriesOIDC(t *testing.T) {
	rec := Record{Event: EventMint, Verdict: VerdictPermit, Reason: GrantsMatched, Principal: "user:alice@corp.example.com",
		Auth: &Auth{Method: "oidc", OIDC: &OIDC{Issuer: "https://sso.example.com/realms/corp", Sub: "8b2e",
			Sid: "3c1f", AMR: []string{"pwd", "otp"}, ACR: "1", AuthTime: "2026-10-06T09:00:00Z"}}}
	var buf bytes.Buffer
	if err := NewJSONLines(&buf).Write(rec); err != nil {
		t.Fatal(err)
	}
	want := `"auth":{"method":"oidc","oidc":{"issuer":"https://sso.example.com/realms/corp","sub":"8b2e","sid":"3c1f","amr":["pwd","otp"],"acr":"1","auth_time":"2026-10-06T09:00:00Z"}}`
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("record %s does not carry %s", buf.String(), want)
	}
}

func TestRevocationNamesAnOIDCSession(t *testing.T) {
	rec := Record{Event: EventRevoke, Verdict: VerdictDeny, Reason: CredentialRevoked,
		Revocation: &Revocation{By: "sid", OIDCIssuer: "https://sso.example.com/realms/corp", Sid: "3c1f",
			At: "2026-10-06T10:00:00Z", Origin: "backchannel_logout https://sso.example.com/realms/corp"}}
	var buf bytes.Buffer
	if err := NewJSONLines(&buf).Write(rec); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"by":"sid"`, `"oidc_issuer":"https://sso.example.com/realms/corp"`, `"sid":"3c1f"`} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("record %s lacks %s", buf.String(), want)
		}
	}
	if strings.Contains(buf.String(), `"sub"`) || strings.Contains(buf.String(), `"principals"`) {
		t.Fatalf("an empty sub or principals is written: %s", buf.String())
	}
	rec.Revocation.Principals = []string{"user:alice@example.com", "user:alice2@example.com"}
	buf.Reset()
	if err := NewJSONLines(&buf).Write(rec); err != nil {
		t.Fatal(err)
	}
	if want := `"principals":["user:alice@example.com","user:alice2@example.com"]`; !strings.Contains(buf.String(), want) {
		t.Fatalf("record %s lacks %s", buf.String(), want)
	}
}
