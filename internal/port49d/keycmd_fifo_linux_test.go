package port49d

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A named pipe is not a copied key, and opening it must not wait for a writer that never comes:
// --import is refused at once and nothing is written.
func TestKeySealingImportRefusesAFifoWithoutHanging(t *testing.T) {
	k := newKT(t)
	fifo := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("no named pipes here:", err)
	}
	done := make(chan int, 1)
	go func() { _, _, code := k.seal("--import", fifo); done <- code }()
	select {
	case code := <-done:
		if code != 1 {
			t.Errorf("exit %d, want 1", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("--import of a named pipe hangs")
	}
	k.wantNames("a fifo import")
}
