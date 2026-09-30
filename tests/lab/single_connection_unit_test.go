//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The line singleConnection types on NX-OS is the shape the N9Kv's own `?`
// allows (tests/lab/results/single-connection-syntax-cisco_nxos.md): after
// `single-connection` it offers only <CR>, so nothing may follow it; after
// `key 0 <key>` it offers single-connection. The note is read here, so the
// line and the measurement cannot drift apart.
func TestSingleConnectionNXOSLineShape(t *testing.T) {
	places := singleConnectionPlaces("cisco_nxos")
	if len(places) != 1 || len(places[0].lines) != 1 {
		t.Fatalf("NX-OS places: %+v", places)
	}
	line := places[0].lines[0]
	if want := "tacacs-server host 172.100.100.1 key 0 " + labKeyDefault + " single-connection"; line != want {
		t.Errorf("NX-OS line %q, want the key before single-connection and nothing after it",
			strings.ReplaceAll(line, labKeyDefault, "<key>"))
	}
	if strings.Contains(places[0].said, labKeyDefault) {
		t.Error("the note's line carries the key")
	}
	raw, err := os.ReadFile(filepath.Join("results", "single-connection-syntax-cisco_nxos.md"))
	if err != nil {
		t.Fatal(err)
	}
	help := func(ask string) string {
		_, rest, ok := strings.Cut(string(raw), "### `"+ask+"`")
		if !ok {
			t.Fatalf("the note has no section for %q", ask)
		}
		_, block, _ := strings.Cut(rest, "```\n")
		block, _, _ = strings.Cut(block, "```")
		return block
	}
	if after := help("tacacs-server host 172.100.100.1 single-connection ?"); helpOffers(after, "key") ||
		!strings.Contains(after, "<CR>") {
		t.Errorf("the note's help after single-connection:\n%s", after)
	}
	if !helpOffers(help("tacacs-server host 172.100.100.1 key 0 <key> ?"), "single-connection") {
		t.Error("the note's help after key 0 <key> does not offer single-connection")
	}
	// The other platforms keep the lines their runs set.
	if eos := singleConnectionPlaces("arista_eos")[0].lines[0]; eos !=
		"tacacs-server host 172.100.100.1 single-connection key 0 "+labKeyDefault {
		t.Errorf("EOS line changed: %q", strings.ReplaceAll(eos, labKeyDefault, "<key>"))
	}
}

func TestHelpOffersReadsTheListNotTheEcho(t *testing.T) {
	echoOnly := "tacacs-server host 172.100.100.1 single-connection ?\n  <CR>   \n"
	listed := "tacacs-server host 172.100.100.1 ?\n  key                TACACS+ shared secret\n" +
		"  single-connection  Use single connection for this Tacacs+ server\n"
	if helpOffers(echoOnly, "single-connection") || !helpOffers(listed, "single-connection") {
		t.Error("helpOffers read the echoed half line as a choice, or missed a listed one")
	}
}
