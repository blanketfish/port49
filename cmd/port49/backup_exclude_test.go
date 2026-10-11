package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The directory is marked for the backup tools that honour CACHEDIR.TAG: the
// standard signature first, 0644, and a second mark changes nothing.
func TestTheIssuedDirectoryIsMarkedExcludedFromBackups(t *testing.T) {
	dir := filepath.Join(privateDir(t), "issued")
	if err := markIssuedDir(dir); err != nil {
		t.Fatal(err)
	}
	tag := filepath.Join(dir, "CACHEDIR.TAG")
	raw, err := os.ReadFile(tag)
	fi, serr := os.Stat(tag)
	if err != nil || serr != nil || !strings.HasPrefix(string(raw), "Signature: 8a477f597d28d172789f06886806bc55\n") ||
		!strings.Contains(string(raw), "port49") || fi.Mode().Perm() != 0o644 {
		t.Fatalf("%q %v %v", raw, fi, err)
	}
	if di, err := os.Stat(dir); err != nil || di.Mode().Perm() != 0o700 {
		t.Fatalf("the directory: %v %v", di, err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(tag, old, old); err != nil {
		t.Fatal(err)
	}
	if err := markIssuedDir(dir); err != nil {
		t.Fatal(err)
	}
	if fi2, err := os.Stat(tag); err != nil || !fi2.ModTime().Before(time.Now().Add(-30*time.Minute)) {
		t.Fatalf("a second mark rewrote the tag: %v %v", fi2, err)
	}
}

// A tag without the signature is not one: it is replaced.
func TestAWrongCacheDirTagIsReplaced(t *testing.T) {
	dir := filepath.Join(privateDir(t), "issued")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "CACHEDIR.TAG"), []byte("nothing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := markIssuedDir(dir); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "CACHEDIR.TAG"))
	if !strings.HasPrefix(string(raw), cacheDirTagSignature) {
		t.Fatalf("%q", raw)
	}
}

// Time Machine's attribute is what `tmutil addexclusion` writes: a binary
// plist of the string com.apple.backupd, 61 bytes, its trailer pointing at
// the one object and the offset table.
func TestTheTimeMachineAttributeIsABinaryPlistOfBackupd(t *testing.T) {
	b := backupdPlist()
	if len(b) != 61 || !bytes.HasPrefix(b, []byte("bplist00")) || !bytes.Contains(b, []byte("com.apple.backupd")) {
		t.Fatalf("%d bytes: %q", len(b), b)
	}
	trailer := b[len(b)-32:]
	if trailer[6] != 1 || trailer[7] != 1 || binary.BigEndian.Uint64(trailer[8:]) != 1 ||
		binary.BigEndian.Uint64(trailer[16:]) != 0 {
		t.Fatalf("trailer %v", trailer)
	}
	at := binary.BigEndian.Uint64(trailer[24:])
	if at != 28 || b[at] != 8 || b[8] != 0x5f || b[9] != 0x10 || b[10] != 17 {
		t.Fatalf("offset table at %d: %v", at, b)
	}
}
