package serialmask

import (
	"strings"
	"testing"
)

// TestMaskSerialMatchesTheL60Rule is L60's TestUnitRedactMasksTheSerial input:
// the rule moved here from the L60 harness must give the same output.
func TestMaskSerialMatchesTheL60Rule(t *testing.T) {
	in := `PIN for YubiKey PIV #12345678: token "YubiKey PIV #12345678" serial 12345678; ` +
		`pkcs11:token=YubiKey%20PIV%20%2312345678;id=%01; ends 2026-10-14T10:00:00Z`
	got := MaskSerial(in)
	if strings.Contains(got, "12345678") || !strings.Contains(got, "2026-10-14T10:00:00Z") {
		t.Fatalf("%q", got)
	}
	want := `PIN for YubiKey PIV #<serial>: token "YubiKey PIV #<serial>" serial <serial>; ` +
		`pkcs11:token=YubiKey%20PIV%20%23<serial>;id=%01; ends 2026-10-14T10:00:00Z`
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}
