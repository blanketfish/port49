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
