package labpcap

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRedactDirTakesEachCapturesOwnKey is L28's rotation capture: a file
// taken under another key is redacted under the key KeyFor names for it, and
// every other file under Key. A pass that used Key for the rotation capture
// would frame its bodies as noise and either refuse the file or miss the
// credential in it.
func TestRedactDirTakesEachCapturesOwnKey(t *testing.T) {
	in, out := t.TempDir(), t.TempDir()
	for _, name := range []string{"login-x.pcap", "rotated-x.pcap"} {
		if err := os.WriteFile(filepath.Join(in, name), fullRun(t, false), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The synthetic captures are under synthKey. Key is set wrong, and KeyFor
	// names the right one for one file only.
	opt := synthOptions()
	opt.Key = "not-the-key"
	opt.KeyFor = func(name string) string {
		if name == "rotated-x.pcap" {
			return synthKey
		}
		return ""
	}
	res, err := RedactDir(in, out, opt)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]error{}
	for _, r := range res {
		got[r.Name] = r.Err
	}
	if got["rotated-x.pcap"] != nil {
		t.Errorf("the capture KeyFor keyed was refused: %v", got["rotated-x.pcap"])
	}
	if got["login-x.pcap"] == nil {
		t.Error("the capture KeyFor left to Key was redacted under the wrong key without complaint")
	}
	if _, err := os.Stat(filepath.Join(out, "rotated-x.pcap")); err != nil {
		t.Errorf("no evidence written for the keyed capture: %v", err)
	}
}
