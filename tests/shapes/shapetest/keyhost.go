package shapetest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// KeyHostRoot is the root the host-key guard looks under; a unit test points it at a fake tree.
var KeyHostRoot = "/"

// KeyHostOverride is the environment variable that lets a smoke run on a host with a TPM or a
// Yubico key. Agents never set it; whether a machine sets it is its owner's decision.
const KeyHostOverride = "PORT49_SMOKE_ON_KEY_HOST"

const yubicoVendor = "1050"

// KeyHostDevice names the first TPM or Yubico hidraw device under root, or "". It only stats the
// device nodes and reads sysfs text (idVendor, the HID_ID line of uevent): it never opens a device,
// which a read of a TPM or a key could answer.
func KeyHostDevice(root string) string {
	for _, d := range []string{"/dev/tpm0", "/dev/tpmrm0"} {
		if _, err := os.Lstat(filepath.Join(root, d)); err == nil {
			return d
		}
	}
	hid, _ := filepath.Glob(filepath.Join(root, "sys", "class", "hidraw", "hidraw*"))
	for _, h := range hid {
		if yubico(h) {
			return "/dev/" + filepath.Base(h) + " (a Yubico device)"
		}
	}
	return ""
}

// yubico is whether the hidraw class entry h belongs to a USB device of Yubico's vendor id.
func yubico(h string) bool {
	if dev, err := filepath.EvalSymlinks(filepath.Join(h, "device")); err == nil {
		if b, err := os.ReadFile(filepath.Join(dev, "uevent")); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				// HID_ID=0003:00001050:00000407 (bus:vendor:product)
				if f := strings.Split(strings.TrimPrefix(l, "HID_ID="), ":"); strings.HasPrefix(l, "HID_ID=") && len(f) == 3 &&
					strings.TrimLeft(strings.ToLower(f[1]), "0") == yubicoVendor {
					return true
				}
			}
		}
		for d, i := dev, 0; i < 6 && d != filepath.Dir(d); d, i = filepath.Dir(d), i+1 {
			if b, err := os.ReadFile(filepath.Join(d, "idVendor")); err == nil {
				return strings.TrimSpace(string(b)) == yubicoVendor
			}
		}
	}
	return false
}

// KeyHostRefusal is the one-line refusal for a host that has a TPM or a Yubico key, or "" when the
// host is clean or the override is set.
func KeyHostRefusal(root string) string {
	if os.Getenv(KeyHostOverride) == "1" {
		return ""
	}
	if d := KeyHostDevice(root); d != "" {
		return fmt.Sprintf("refusing to start: %s exists on this host, and this smoke runs a container with CAP_SYS_ADMIN and no AppArmor (or a privileged kind node); set %s=1 to run it anyway", d, KeyHostOverride)
	}
	return ""
}

// RefuseOnKeyHost fails the test first thing on a host with a TPM or a Yubico key (see KeyHostRefusal).
func RefuseOnKeyHost(t *testing.T) {
	t.Helper()
	if r := KeyHostRefusal(KeyHostRoot); r != "" {
		t.Fatal(r)
	}
}
