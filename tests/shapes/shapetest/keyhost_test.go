package shapetest

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func mk(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// hidraw makes /sys/class/hidraw/<name>/device as the kernel does: a link into the HID device, whose
// parents are the USB interface and the USB device holding idVendor.
func hidraw(t *testing.T, root, name, vendor, hidID string) {
	t.Helper()
	usb := filepath.Join(root, "sys", "devices", "pci0", "usb1", "1-2")
	mk(t, usb, "idVendor", vendor+"\n")
	hid := filepath.Join(usb, "1-2:1.0", "0003:"+name)
	mk(t, hid, "uevent", "DRIVER=hid-generic\nHID_ID="+hidID+"\n")
	cls := filepath.Join(root, "sys", "class", "hidraw", name)
	if err := os.MkdirAll(cls, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(hid, filepath.Join(cls, "device")); err != nil {
		t.Fatal(err)
	}
}

func TestKeyHostGuard(t *testing.T) {
	t.Setenv(KeyHostOverride, "")
	t.Run("a clean host", func(t *testing.T) {
		root := t.TempDir()
		hidraw(t, root, "hidraw0", "046d", "0003:0000046D:0000C52B") // a mouse
		mk(t, root, "dev/null", "")
		if r := KeyHostRefusal(root); r != "" {
			t.Errorf("refused a clean host: %s", r)
		}
	})
	for _, dev := range []string{"tpm0", "tpmrm0"} {
		t.Run(dev, func(t *testing.T) {
			root := t.TempDir()
			mk(t, root, "dev/"+dev, "")
			r := KeyHostRefusal(root)
			if !strings.Contains(r, "/dev/"+dev) || !strings.Contains(r, KeyHostOverride+"=1") || strings.Contains(r, "\n") {
				t.Errorf("want one line naming /dev/%s and the override: %q", dev, r)
			}
		})
	}
	t.Run("a Yubico hidraw by its uevent", func(t *testing.T) {
		root := t.TempDir()
		hidraw(t, root, "hidraw3", "9999", "0003:00001050:00000407")
		if r := KeyHostRefusal(root); !strings.Contains(r, "/dev/hidraw3") {
			t.Errorf("%q", r)
		}
	})
	t.Run("a Yubico hidraw by its USB idVendor", func(t *testing.T) {
		root := t.TempDir()
		hidraw(t, root, "hidraw1", "1050", "0003:00000000:00000000")
		if r := KeyHostRefusal(root); !strings.Contains(r, "/dev/hidraw1") {
			t.Errorf("%q", r)
		}
	})
	t.Run("the override", func(t *testing.T) {
		root := t.TempDir()
		mk(t, root, "dev/tpm0", "")
		t.Setenv(KeyHostOverride, "1")
		if r := KeyHostRefusal(root); r != "" {
			t.Errorf("the override was ignored: %s", r)
		}
		t.Setenv(KeyHostOverride, "yes")
		if KeyHostRefusal(root) == "" {
			t.Error("only 1 is the override")
		}
	})
}

// The guard never opens a device: a FIFO blocks an open for read until a writer arrives, and the
// guard must still answer.
func TestKeyHostGuardOnlyStatsTheDevices(t *testing.T) {
	t.Setenv(KeyHostOverride, "")
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "dev"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "dev", "tpmrm0"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() { done <- KeyHostRefusal(root) }()
	select {
	case r := <-done:
		if !strings.Contains(r, "/dev/tpmrm0") {
			t.Errorf("%q", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the guard blocked on the device: it opened it")
	}
}
