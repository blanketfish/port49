package shapetest

import (
	"errors"
	"fmt"
	"io/fs"
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

// KeyHostDevice names the first TPM or Yubico device under root, or "". It only stats device nodes and
// reads sysfs text (idVendor, the HID_ID line of uevent): it never opens a device. A security key
// speaking only CCID (PIV) has no hidraw node, so the USB bus is scanned for Yubico's vendor id as well.
// A directory that exists but cannot be read is an error, never "none": the guard fails closed.
func KeyHostDevice(root string) (string, error) {
	for _, d := range []string{"/dev/tpm0", "/dev/tpmrm0"} {
		if _, err := os.Lstat(filepath.Join(root, d)); err == nil {
			return d, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
	}
	hid, err := readDirs(filepath.Join(root, "sys", "class", "hidraw"))
	if err != nil {
		return "", err
	}
	for _, h := range hid {
		y, err := yubicoHID(h)
		if err != nil {
			return "", err
		}
		if y {
			return "/dev/" + filepath.Base(h) + " (a Yubico device)", nil
		}
	}
	usb, err := readDirs(filepath.Join(root, "sys", "bus", "usb", "devices"))
	if err != nil {
		return "", err
	}
	for _, u := range usb {
		v, err := os.ReadFile(filepath.Join(u, "idVendor"))
		if errors.Is(err, fs.ErrNotExist) {
			continue // an interface, not a device
		}
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(string(v)) == yubicoVendor {
			return "the USB device " + strings.TrimPrefix(u, root) + " (Yubico)", nil
		}
	}
	return "", nil
}

// readDirs lists the entries of dir as paths; a missing dir has none.
func readDirs(dir string) ([]string, error) {
	es, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range es {
		out = append(out, filepath.Join(dir, e.Name()))
	}
	return out, nil
}

// yubicoHID is whether the hidraw class entry h belongs to a device of Yubico's vendor id.
func yubicoHID(h string) (bool, error) {
	dev, err := filepath.EvalSymlinks(filepath.Join(h, "device"))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	b, err := os.ReadFile(filepath.Join(dev, "uevent"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	for _, l := range strings.Split(string(b), "\n") {
		// HID_ID=0003:00001050:00000407 (bus:vendor:product)
		if f := strings.Split(strings.TrimPrefix(l, "HID_ID="), ":"); strings.HasPrefix(l, "HID_ID=") && len(f) == 3 &&
			strings.TrimLeft(strings.ToLower(f[1]), "0") == yubicoVendor {
			return true, nil
		}
	}
	for d, i := dev, 0; i < 6 && d != filepath.Dir(d); d, i = filepath.Dir(d), i+1 {
		v, err := os.ReadFile(filepath.Join(d, "idVendor"))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		return strings.TrimSpace(string(v)) == yubicoVendor, nil
	}
	return false, nil
}

// KeyHostRefusal is the one-line refusal for a host that has a TPM or a Yubico key, or cannot be
// told apart from one, or "" when the host is clean or the override is set.
func KeyHostRefusal(root string) string {
	if os.Getenv(KeyHostOverride) == "1" {
		return ""
	}
	d, err := KeyHostDevice(root)
	if err != nil {
		return fmt.Sprintf("refusing to start: cannot tell whether a TPM or security key is attached: %v; set %s=1 to run it anyway", err, KeyHostOverride)
	}
	if d != "" {
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
