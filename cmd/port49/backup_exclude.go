package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/rhwendt/port49/internal/userconfig"
)

// cacheDirTagSignature is the first line of a CACHEDIR.TAG, the mark borg,
// restic --exclude-caches and GNU tar --exclude-caches honour
// (https://bford.info/cachedir/).
const cacheDirTagSignature = "Signature: 8a477f597d28d172789f06886806bc55"

const cacheDirTag = cacheDirTagSignature + "\n" +
	"# This directory holds a key and certificate port49 issued: a session, not a file to back up.\n" +
	"# port49 writes this file; see https://bford.info/cachedir/ for what it means.\n"

// backupdPlist is the value `tmutil addexclusion` writes in the
// com.apple.metadata:com_apple_backup_excludeItem attribute: a binary plist
// whose one object is the string "com.apple.backupd". It is built here, not
// kept as a constant, so the bytes can be read against the format: the
// header, the object (an ASCII string over 14 characters: 0x5f, then its
// length as a one-byte integer), the offset table, and the 32-byte trailer.
func backupdPlist() []byte {
	const s = "com.apple.backupd"
	var b bytes.Buffer
	b.WriteString("bplist00")
	b.Write([]byte{0x5f, 0x10, byte(len(s))})
	b.WriteString(s)
	tableAt := b.Len()
	b.WriteByte(8) // the one object starts after the 8-byte header
	b.Write(make([]byte, 6))
	b.Write([]byte{1, 1})                   // offset size, object reference size
	b.Write([]byte{0, 0, 0, 0, 0, 0, 0, 1}) // objects
	b.Write(make([]byte, 8))                // the top object is object 0
	b.Write([]byte{0, 0, 0, 0, 0, 0, 0, byte(tableAt)})
	return b.Bytes()
}

// markIssuedDir marks the directory holding the issued key and certificate
// as one to leave out of a backup: a CACHEDIR.TAG for the tools that honour
// one, and on macOS Time Machine's own exclusion (excludeFromTimeMachine). The
// key is the person's session until the certificate ends, and a restore
// within that holds it; asking every person on every host to exclude it
// themselves is a step no fleet takes. It is idempotent, and a failure is a
// warning for the caller, never a refused login.
func markIssuedDir(dir string) error {
	dir, err := userconfig.PrivateDir(dir, "port49-issued directory")
	if err != nil {
		return err
	}
	return errors.Join(writeCacheDirTag(dir), excludeFromTimeMachine(dir))
}

// writeCacheDirTag writes dir/CACHEDIR.TAG, 0644, unless a tag with the
// signature is there.
func writeCacheDirTag(dir string) error {
	path := filepath.Join(dir, "CACHEDIR.TAG")
	if b, err := os.ReadFile(path); err == nil && bytes.HasPrefix(b, []byte(cacheDirTagSignature)) {
		return nil
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	// Written through a temporary renamed over it, as everything port49 keeps
	// here is, so a tool never reads half of it.
	tmp, err := os.CreateTemp(dir, ".CACHEDIR.TAG.*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(cacheDirTag); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
