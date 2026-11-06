//go:build linux

package port49d

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestARecordAnotherUserOwnsIsUnreadable(t *testing.T) {
	f := floorAt(t)
	f.read(1000, 1010)
	f.saveIfDirty()
	ownedAs(t, 4242, filepath.Base(f.path))
	f.open()
	if !strings.Contains(f.out.String(), "every token in the store is refused") {
		t.Fatalf("a record another user owns was read: %q", f.out.String())
	}
	f.read(1000, 1011)
	if f.said(dropped) != 1 {
		t.Fatal("the first read was not a drop")
	}
}
