package inventory

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/sot"
	"github.com/rhwendt/port49/internal/sot/sottest"
)

// fencedFile writes body where the fence passes it: a directory only its
// owner can write, a file only its owner can.
func fencedFile(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAFileSourceReadsTheInventoryFile(t *testing.T) {
	src := FileSource{SourceName: "lab_file", Path: fencedFile(t,
		"devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.0.1], attributes: {site: dc1}}\n")}
	inv, err := src.Fetch(context.Background())
	if err != nil || len(inv.Devices) != 1 || inv.Devices[0].Attributes["site"] != "dc1" {
		t.Fatalf("%+v %v", inv, err)
	}
}

// Plan 6b owner decision 3: the service assigns no key.
func TestAFileSourceThatAssignsAKeyIsRefused(t *testing.T) {
	pin := FileSource{SourceName: "lab_file", Path: fencedFile(t,
		"devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.0.1], key_ref: lab_key}\n")}
	if _, err := pin.Fetch(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "device leaf-01 pins key_ref") ||
		!strings.Contains(err.Error(), "{match: {name: leaf-01}, key_ref: ...}") {
		t.Fatalf("pin: %v", err)
	}
	groups := FileSource{SourceName: "lab_file", Path: fencedFile(t,
		"devices: []\nkey_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]\n")}
	if _, err := groups.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "carries key_groups") {
		t.Fatalf("groups: %v", err)
	}
}

// A name that cannot reach a line as it is goes by its position, and the fix
// is at the source: a key group cannot match a position.
func TestAPinOnAnUnprintableNameIsRefusedByPosition(t *testing.T) {
	src := FileSource{SourceName: "lab_file", Path: fencedFile(t,
		"devices:\n  - {name: leaf 01, platform: arista_eos, addresses: [10.0.0.1], key_ref: lab_key}\n")}
	_, err := src.Fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "device #0 pins key_ref") ||
		strings.Contains(err.Error(), "leaf 01") || strings.Contains(err.Error(), "{match: {name: #0}") ||
		!strings.Contains(err.Error(), "fix its name at the source") {
		t.Fatalf("got %v", err)
	}
}

// A decode error prints a line and a category, never the file's text.
func TestAFileSourceDecodeErrorDoesNotEchoTheFile(t *testing.T) {
	src := FileSource{SourceName: "lab_file", Path: fencedFile(t,
		"devices:\n  - {name: leaf-01, platform: arista_eos, attributes: p49_s3cr3t_t0ken}\n")}
	_, err := src.Fetch(context.Background())
	if err == nil || strings.Contains(err.Error(), "s3cr3t") || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("got %v", err)
	}
}

// The source file decides access within one pull: it is read behind the
// write fence (Task 6).
func TestAFileSourceOthersCouldWriteIsRefused(t *testing.T) {
	p := fencedFile(t, "devices: []\n")
	if err := os.Chmod(p, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileSource{SourceName: "lab_file", Path: p}).Fetch(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("got %v", err)
	}
}

func TestNewSourcesBuildsEachConfiguredSource(t *testing.T) {
	nb := sottest.New(t, "netbox-4", 1)
	srcs, err := NewSources([]SourceConfig{{Name: "a", Type: "file", Path: "/x"},
		{Name: "b", Type: "netbox", URL: nb.URL, CAFile: nb.CAFile, Token: sot.NewSecret("t"), API: "auto", PageSize: 50,
			Mapping: sot.Mapping{Addresses: sot.Addresses{Primary: true}}}}, io.Discard)
	if err != nil || len(srcs) != 2 || srcs[1].Name() != "b" {
		t.Fatalf("%v %v", srcs, err)
	}
	if _, ok := srcs[1].(*sot.Source); !ok {
		t.Fatalf("%T", srcs[1])
	}
	// The CA file is read at start: a missing one stops the start.
	if _, err := NewSources([]SourceConfig{{Name: "b", Type: "netbox", URL: nb.URL, CAFile: "/nonexistent/ca.pem",
		Token: sot.NewSecret("t")}}, io.Discard); err == nil || !strings.Contains(err.Error(), "source b: ca_file") {
		t.Fatalf("got %v", err)
	}
}
