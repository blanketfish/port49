//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ed25519 blob of an arbitrary 51-byte string; the fingerprint is the SHA256 of the decoded bytes.
const l66E3BlobA = "AAAAC3NzaC1lZDI1NTE5AAAAIH0P+6ijkIiL+Y5AmSG0k1mMrRl20w/dZDaAa9YOph0d"
const l66E3BlobB = "AAAAC3NzaC1lZDI1NTE5AAAAIOaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestL66ScanKeys(t *testing.T) {
	out := "# 10.0.0.1:22 SSH-2.0-x\n10.0.0.1 ssh-ed25519 " + l66E3BlobA + "\n10.0.0.1 ssh-rsa AAAA\n"
	got := l66ScanKeys(out)
	if len(got) != 2 || got[0] != "ssh-ed25519 "+l66E3BlobA {
		t.Fatalf("keys = %v", got)
	}
}

func TestL66KeyFP(t *testing.T) {
	fp := l66KeyFP(l66E3BlobA)
	if !strings.HasPrefix(fp, "SHA256:") || len(fp) != len("SHA256:")+43 {
		t.Fatalf("fingerprint = %q", fp)
	}
	if l66KeyFP("not base64!") != "" {
		t.Fatal("a bad blob has a fingerprint")
	}
}

func TestL66GradeE3(t *testing.T) {
	dev, st := []string{"ssh-ed25519 " + l66E3BlobA}, []string{"ssh-ed25519 " + l66E3BlobB}
	msg := "host_key_changed: " + l66KeyFP(l66E3BlobA) + " " + l66KeyFP(l66E3BlobB)
	good := l66E3In{Failed: true, ErrText: msg, Dev: dev, Stand: st}
	if ok, why := l66GradeE3(good); !ok {
		t.Fatalf("a refusal naming both keys with nothing minted failed: %s", why)
	}
	for name, mut := range map[string]func(*l66E3In){
		"played":   func(i *l66E3In) { i.Failed = false },
		"no code":  func(i *l66E3In) { i.ErrText = strings.ReplaceAll(i.ErrText, "host_key_changed", "x") },
		"one key":  func(i *l66E3In) { i.ErrText = "host_key_changed: " + l66KeyFP(l66E3BlobA) },
		"minted":   func(i *l66E3In) { i.Mints = 1 },
		"packets":  func(i *l66E3In) { i.Packets = 3 },
		"redeem":   func(i *l66E3In) { i.Redeems = 1 },
		"standin":  func(i *l66E3In) { i.StandinConnects = 1 },
		"no share": func(i *l66E3In) { i.Stand = []string{"ssh-rsa " + l66E3BlobB} },
	} {
		in := good
		mut(&in)
		if ok, _ := l66GradeE3(in); ok {
			t.Errorf("%s: graded as a pass", name)
		}
	}
}

func TestL66KeywordPlay(t *testing.T) {
	pb := l66Playbook("once", l66Platforms["arista_eos"], 1, "")
	got := l66KeywordPlay(pb)
	if !strings.Contains(got, "  connection: ansible.netcommon.network_cli\n") || !strings.Contains(got, "L66PROBE[") ||
		strings.Index(got, "L66PROBE") > strings.Index(got, "mint once") {
		t.Fatalf("play = %s", got)
	}
}

func TestL66E3Heading(t *testing.T) {
	for _, only := range []string{"e3", "e3d"} {
		title, run := l66E3Heading(only, "2026-10-16")
		if title != "## ("+only+") — 2026-10-16\n\n" || run != "`PORT49_L66_ONLY="+only+"`" {
			t.Errorf("%s: title %q run %q", only, title, run)
		}
	}
}

func TestLabGuardAt(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "STOP")
	if err := labGuardAt(sentinel, dir, 1); err != nil {
		t.Fatalf("no sentinel and room: %v", err)
	}
	if err := labGuardAt(sentinel, dir, 1<<40); err == nil || !strings.Contains(err.Error(), "floor") {
		t.Fatalf("a floor above the free space: %v", err)
	}
	if err := os.WriteFile(sentinel, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := labGuardAt(sentinel, dir, 1); err == nil || !strings.Contains(err.Error(), "STOP") {
		t.Fatalf("a sentinel: %v", err)
	}
}
