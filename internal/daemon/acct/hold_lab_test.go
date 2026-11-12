//go:build port49_lab_acct_hold

package acct

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/tacacs/wire"
)

// The hold build holds a reply only while the lab's control file exists: the
// device's own accounting before L94 c4's clean point drains unheld.
func TestTheHoldBuildHoldsOnlyWhileItsControlFileExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hold")
	if labHoldOnAt(path) {
		t.Fatal("the control file is absent, and a reply was held")
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the check created the control file: %v", err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if !labHoldOnAt(path) {
			t.Fatal("the control file is present, and no reply was held")
		}
	}
	// One line per held reply: the harness grades every accounting record
	// of the cell against this count.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(b), "\n"); got != 2 {
		t.Errorf("the control file counts %d held replies, want 2", got)
	}
	if labHoldOnAt("") {
		t.Error("no control file named, and a reply was held")
	}
}

// PORT49_LAB_ACCT_HOLD_FILE unset: no reply is held. The test never sets it.
func TestTheHoldBuildHoldsNothingWithItsVariableUnset(t *testing.T) {
	if os.Getenv(labAcctHoldFileEnv) != "" {
		t.Skipf("%s is set in this environment", labAcctHoldFileEnv)
	}
	if labHoldFile != "" || labHoldOn() {
		t.Errorf("the variable is unset, and the hold build holds (file %q)", labHoldFile)
	}
}

// Handle consults the control file on every request.
func TestHandleHoldsTheReplyOnlyWhileTheControlFileExists(t *testing.T) {
	h, _, _, stop := setup(t)
	defer stop()
	path := filepath.Join(t.TempDir(), "hold")
	saved := labHoldFile
	labHoldFile = path
	defer func() { labHoldFile = saved }()
	took := func() time.Duration {
		t0 := time.Now()
		h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty0", "task_id=1", "service=shell", "cmd=show version"))
		return time.Since(t0)
	}
	if d := took(); d >= labAcctHold {
		t.Errorf("no control file, and the reply took %s", d)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if d := took(); d < labAcctHold {
		t.Errorf("the control file exists, and the reply took %s, not the hold's %s", d, labAcctHold)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if d := took(); d >= labAcctHold {
		t.Errorf("the control file was removed, and the reply took %s", d)
	}
}
