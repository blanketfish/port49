package port49d

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/inventory"
)

// scriptService answers from fields a test sets, and counts what it was asked.
type scriptService struct {
	raw               []byte
	versionErr        error
	versions, bundles int
	lastIfNoneMatch   string
}

func (s *scriptService) Version(context.Context) (inventory.VersionInfo, error) {
	s.versions++
	return inventory.VersionInfo{ETag: bundle.ETag(s.raw)}, s.versionErr
}

func (s *scriptService) Bundle(_ context.Context, etag string) ([]byte, string, bool, error) {
	s.bundles++
	s.lastIfNoneMatch = etag
	if e := bundle.ETag(s.raw); etag == e {
		return nil, e, true, nil
	}
	return s.raw, bundle.ETag(s.raw), false, nil
}

func newFetcher(svc fetchClient, keys []ed25519.PublicKey) *fetcher {
	return &fetcher{client: svc, keys: func() []ed25519.PublicKey { return keys }, url: "https://inv.test:8443",
		interval: time.Hour, metrics: metrics.New(prometheus.NewRegistry()), proc: "port49d"}
}

func TestAnUnchangedVersionCostsOneSmallRequest(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	svc := &scriptService{raw: sealedDoc(t, key, 1, 2)}
	f := newFetcher(svc, []ed25519.PublicKey{pub})
	if d, ok := f.once(context.Background()); !ok || d.pub == nil || d.pub.Doc.Sequence != 1 {
		t.Fatalf("%+v %v", d, ok)
	}
	if d, ok := f.once(context.Background()); !ok || !d.unchanged || svc.bundles != 1 || svc.versions != 2 {
		t.Fatalf("%+v: %d bundle and %d version calls", d, svc.bundles, svc.versions)
	}
}

func TestAFailureIsSaidOnceAndTheRecoveryOnce(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	svc := &scriptService{raw: sealedDoc(t, key, 1, 2), versionErr: errors.New("dial tcp: connection refused")}
	f := newFetcher(svc, []ed25519.PublicKey{pub})
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	for i := 0; i < 3; i++ {
		if _, ok := f.once(context.Background()); ok {
			t.Fatal("a failure handed something over")
		}
	}
	svc.versionErr = nil
	f.once(context.Background())
	f.once(context.Background())
	if strings.Count(out.String(), "did not answer (dial tcp: connection refused)") != 1 ||
		strings.Count(out.String(), "answers again") != 1 {
		t.Fatalf("%s", out.String())
	}
	if testutil.ToFloat64(f.metrics.InventoryFetches.WithLabelValues("failed")) != 3 {
		t.Fatal("failed fetches not counted")
	}
}

func TestADocumentThatDoesNotVerifyIsHandedOverWithItsError(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	svc := &scriptService{raw: sealedDoc(t, other, 1, 2)}
	f := newFetcher(svc, []ed25519.PublicKey{pub})
	d, ok := f.once(context.Background())
	if !ok || d.err == nil || d.pub != nil || len(d.raw) == 0 {
		t.Fatalf("%+v", d)
	}
	if testutil.ToFloat64(f.metrics.InventoryFetches.WithLabelValues("invalid")) != 1 {
		t.Fatal("not counted invalid")
	}
}

// A poke (SIGHUP) forgets the etag held, so the document comes whole again.
func TestAPokeFetchesTheDocumentAgain(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	svc := &scriptService{raw: sealedDoc(t, key, 1, 2)}
	f := newFetcher(svc, []ed25519.PublicKey{pub})
	f.once(context.Background())
	f.etag = "" // what run does on a poke
	if d, ok := f.once(context.Background()); !ok || d.pub == nil || svc.lastIfNoneMatch != "" || svc.bundles != 2 {
		t.Fatalf("%+v: If-None-Match %q", d, svc.lastIfNoneMatch)
	}
}

// Conflict scan F8: an ask cut short by shutdown says nothing.
func TestAShutdownMidAskSaysNothing(t *testing.T) {
	svc := &scriptService{versionErr: context.Canceled}
	f := newFetcher(svc, nil)
	var out syncBuffer
	e := stderr
	defer func() { stderr = e }()
	stderr = &out
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := f.once(ctx); ok || out.String() != "" {
		t.Fatalf("%v %q", ok, out.String())
	}
}

// notModifiedService answers every document ask 304, with an ETag header of
// its own choosing.
type notModifiedService struct{ header string }

func (s notModifiedService) Version(context.Context) (inventory.VersionInfo, error) {
	return inventory.VersionInfo{}, nil
}

func (s notModifiedService) Bundle(context.Context, string) ([]byte, string, bool, error) {
	return nil, s.header, true, nil
}

// Review minor 2: a 304 confirms the etag asked with, never the header's.
func TestANotModifiedConfirmsTheETagAskedWith(t *testing.T) {
	f := newFetcher(notModifiedService{header: `"in-force"`}, nil)
	f.etag = `"refused"`
	if d, ok := f.once(context.Background()); !ok || !d.unchanged || d.etag != `"refused"` {
		t.Fatalf("%+v", d)
	}
}
