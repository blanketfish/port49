package author

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/blob"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
)

func blobFixture(t *testing.T) (*Blob, store.Context) {
	t.Helper()
	st := memory.New(time.Now)
	body, hash, err := blob.Encode(blob.Blob{Platform: "arista_eos", Privilege: 15,
		Attributes: []string{"priv-lvl=15"}, Permit: []string{"**"}, Deny: []string{"show hostname"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutBlob(context.Background(), hash, body, time.Hour); err != nil {
		t.Fatal(err)
	}
	return &Blob{Store: st, Fallback: &Lab{SessionAttributes: []string{"lab-attr=1"}, DenyPrefixes: []string{"show clock"}}},
		store.Context{CtxID: "c", Username: "alice", BlobHash: hash}
}

// A context the broker minted names its blob, and the session reply is the
// blob's attributes — not the lab's.
func TestABlobContextIsAnsweredFromItsBlob(t *testing.T) {
	a, c := blobFixture(t)
	d := a.Session(context.Background(), Request{Context: c})
	if !d.Permit || d.Reason != decision.ContextMatched || len(d.Attributes) != 1 || d.Attributes[0] != "priv-lvl=15" {
		t.Fatalf("session: %+v", d)
	}
	for _, tt := range []struct {
		vector []string
		permit bool
		reason decision.Reason
	}{
		{[]string{"show", "version"}, true, decision.PermitDominates},
		{[]string{"show", "hostname"}, false, decision.NoPermitDominatesDeny},
		// The lab's own deny list does not apply to a blob context.
		{[]string{"show", "clock"}, true, decision.PermitDominates},
	} {
		d := a.Command(context.Background(), Request{Context: c, Vector: tt.vector})
		if d.Permit != tt.permit || d.Reason != tt.reason {
			t.Errorf("Command(%q) = %+v, want permit=%v %s", tt.vector, d, tt.permit, tt.reason)
		}
		if !d.Permit && !strings.HasPrefix(d.ServerMsg, "port49: ") {
			t.Errorf("a denial tells the operator why: %q", d.ServerMsg)
		}
	}
	if d := (&Blob{Store: a.Store, Fallback: a.Fallback}).Command(context.Background(),
		Request{Context: store.Context{BlobHash: c.BlobHash}, Vector: []string{"configure"}}); !d.Permit {
		t.Fatalf("`**` permits configure: %+v", d)
	}
}

// A blob the store cannot produce, or produces wrong, is blob_unavailable: a
// store fault, alertable on its own, never a policy verdict (spec §5.1.1).
func TestAMissingOrCorruptBlobIsBlobUnavailable(t *testing.T) {
	a, c := blobFixture(t)
	missing := c
	missing.BlobHash = blob.HashOf([]byte("nothing was stored under this"))
	if err := a.Store.PutBlob(context.Background(), "sha256:wrong", []byte(`{"platform":"x"}`), time.Hour); err != nil {
		t.Fatal(err)
	}
	corrupt := c
	corrupt.BlobHash = "sha256:wrong"
	// The bytes are the ones named, but a regex is outside the slice's rule
	// subset: Decode refuses it, and a refused blob is no more a verdict than
	// a missing one.
	body := []byte(`{"platform":"arista_eos","privilege":15,"attributes":[],"permit":["/.*/"],"deny":[]}`)
	if err := a.Store.PutBlob(context.Background(), blob.HashOf(body), body, time.Hour); err != nil {
		t.Fatal(err)
	}
	refused := c
	refused.BlobHash = blob.HashOf(body)
	for name, cc := range map[string]store.Context{"missing": missing, "corrupt": corrupt, "refused": refused} {
		if d := a.Session(context.Background(), Request{Context: cc}); d.Permit || d.Reason != decision.BlobUnavailable {
			t.Errorf("%s: session %+v", name, d)
		}
		if d := a.Command(context.Background(), Request{Context: cc, Vector: []string{"show", "version"}}); d.Permit || d.Reason != decision.BlobUnavailable {
			t.Errorf("%s: command %+v", name, d)
		}
	}
}

// A context with no blob — the lab's seeded tokens — is the fallback's.
func TestAContextWithNoBlobIsTheFallbacks(t *testing.T) {
	a, _ := blobFixture(t)
	c := store.Context{CtxID: "c", Username: "alice"}
	if d := a.Session(context.Background(), Request{Context: c}); !d.Permit || d.Attributes[0] != "lab-attr=1" {
		t.Fatalf("session: %+v", d)
	}
	if d := a.Command(context.Background(), Request{Context: c, Vector: []string{"show", "clock"}}); d.Permit {
		t.Fatalf("the lab's deny list applies to a seeded context: %+v", d)
	}
	// With no fallback configured, a context with no blob is denied, not
	// permitted and not a panic.
	a.Fallback = nil
	if d := a.Session(context.Background(), Request{Context: c}); d.Permit || d.Reason != decision.NoRuleMatched {
		t.Fatalf("nil fallback session: %+v", d)
	}
	if d := a.Command(context.Background(), Request{Context: c, Vector: []string{"show", "version"}}); d.Permit || d.Reason != decision.NoRuleMatched {
		t.Fatalf("nil fallback command: %+v", d)
	}
}
