package tpm

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/rhwendt/port49/internal/hwkey"
)

// dialing makes Dial return err for the test and writes a key file to open.
func dialing(t *testing.T, err error) (keyFile string) {
	t.Helper()
	prev := Dial
	Dial = func() (transport.TPMCloser, error) { return nil, err }
	t.Cleanup(func() { Dial = prev })
	pub, priv := testBlobs()
	file, encErr := EncodeTSS2(pub, priv)
	if encErr != nil {
		t.Fatal(encErr)
	}
	keyFile = filepath.Join(t.TempDir(), "k.tpmkey")
	if werr := os.WriteFile(keyFile, file, 0o600); werr != nil {
		t.Fatal(werr)
	}
	return keyFile
}

func TestATPMTheUserMayNotOpenIsNotAbsent(t *testing.T) {
	path := dialing(t, &fs.PathError{Op: "open", Path: "/dev/tpmrm0", Err: syscall.EACCES})
	_, err := Open(path)
	if err == nil || !strings.Contains(err.Error(), "add this user to the tss group, then log in again") {
		t.Fatalf("Open with EACCES = %v, want the tss group advice", err)
	}
	if errors.Is(err, hwkey.ErrKeyAbsent) {
		t.Fatal("a TPM the user may not open is there; it must not read as absent")
	}
}

func TestATPMThatIsNotThereIsAbsent(t *testing.T) {
	path := dialing(t, &fs.PathError{Op: "stat", Path: "/dev/tpmrm0", Err: syscall.ENOENT})
	if _, err := Open(path); !errors.Is(err, hwkey.ErrKeyAbsent) {
		t.Fatalf("Open with no TPM = %v, want ErrKeyAbsent", err)
	}
}

func TestGenerateWithNoTPMWritesNoFile(t *testing.T) {
	dialing(t, errors.New("no tpm"))
	path := filepath.Join(t.TempDir(), "new.tpmkey")
	if _, err := Generate(path); !errors.Is(err, hwkey.ErrKeyAbsent) {
		t.Fatalf("Generate with no TPM = %v, want ErrKeyAbsent", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a failed Generate left %s behind: %v", path, err)
	}
}
