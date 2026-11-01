//go:build hwkey_dlopen

package clientkey

import (
	"io"
	"runtime"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/hwkey/secureenclave"
)

// The client build sends a secure-enclave: reference to the Secure Enclave
// backend (decision 45 ruling 6), which off macOS refuses naming macOS; a
// reference that is not label=NAME is refused before it, as clientkey's.
func TestASecureEnclaveReferenceReachesTheBackend(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("on macOS the backend is real; secureenclave's darwin test covers it")
	}
	prev := secureenclave.Warnings
	secureenclave.Warnings = io.Discard
	t.Cleanup(func() { secureenclave.Warnings = prev })
	pin := []byte("123456")
	_, err := Open("secure-enclave:label=port49.broker_443.aaaaaaaa", pin)
	if err == nil || !strings.Contains(err.Error(), "the Secure Enclave is macOS's, and this is "+runtime.GOOS) {
		t.Fatalf("%v", err)
	}
	if string(pin) != "\x00\x00\x00\x00\x00\x00" {
		t.Errorf("the PIN was not zeroed: %q", pin)
	}
	for _, ref := range []string{"secure-enclave:", "secure-enclave:port49", "secure-enclave:label=a/b"} {
		_, err := Open(ref, nil)
		if err == nil || !strings.HasPrefix(err.Error(), "clientkey: secureenclave: ") {
			t.Errorf("%s: %v", ref, err)
		}
	}
}
