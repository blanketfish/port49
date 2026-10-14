package l60

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

// lockedBuffer is what the self-test's port49 children write, read after.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// The harness end to end with no token and no terminal: it builds port49,
// serves the broker, logs in with a file key, reads GET /status, refreshes,
// mints (the token measured, never shown), meets the touch device with no
// touch key, and stops the agent by its pid. Opt-in (it builds a binary):
// PORT49_L60_SELFTEST=1.
func TestL60SelfTest(t *testing.T) {
	gate(t, gateSelf, "the harness with a file key; no token, no terminal")
	var out lockedBuffer
	dir := t.TempDir()
	h := setupLab(t, "selftest", true, nil, &out, dir)
	ca, err := writeClientCA(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	piv, err := testpki.NewPIV(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b := h.startLabBroker(ca, piv.Anchors())
	cert, key := fileClient(t, ca)
	s := socketIn(t)

	r := h.port49(runOpts{}, loginArgs(b, s, key, cert, "")...)
	h.obsResult("login", r)
	if r.code != 0 || !strings.Contains(r.stdout, "logged in to "+b.url) || h.agentsRunning() != 1 {
		t.Fatalf("login: %+v", r)
	}
	if st := h.obsStatus("status", s); st.KeyState != "present" {
		t.Fatalf("status %+v", st)
	}
	if r := h.port49(runOpts{}, "refresh", "--socket", s); r.code != 0 || !strings.Contains(r.stdout, leafPlain) {
		t.Fatalf("refresh: %+v", r)
	}
	r = h.port49(runOpts{token: true}, "token", "--socket", s, leafPlain)
	h.obsResult("token", r)
	if r.code != 0 || r.tokenBytes == 0 || r.stdout != "" {
		t.Fatalf("token: %+v", r)
	}
	r = h.port49(runOpts{token: true}, "token", "--socket", s, leafTouch)
	h.obsResult("touch_token", r)
	if r.code != 1 || !strings.Contains(r.stderr, "hardware_key_touch") || r.tokenBytes != 0 {
		t.Fatalf("touch device: %+v", r)
	}
	h.statusCost("cost", s, 5)
	h.stopAgent(s)
	if _, err := h.status(s); err == nil {
		t.Fatal("the agent still answers after stopAgent")
	}
	obs, err := os.ReadFile(filepath.Join(dir, fileObs))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"L60 selftest login_code: 0", "L60 selftest token_minted: a ", "L60 selftest cost: n=5"} {
		if !bytes.Contains(obs, []byte(want)) {
			t.Fatalf("observations lack %q:\n%s", want, obs)
		}
	}
	t.Logf("terminal:\n%s\nobservations:\n%s", out.String(), obs)
}
