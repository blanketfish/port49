package hwkey

import (
	"errors"
	"testing"
)

func TestIsRef(t *testing.T) {
	for s, want := range map[string]bool{
		"pkcs11:id=%01?module-path=/x.so": true,
		"tpm:handle=0x81000001":           true,
		"secure-enclave:label=port49":     true,
		"/home/a/.port49/key.pem":         false,
		"~/key.pem":                       false,
		"./pkcs11:odd":                    false,
		"":                                false,
	} {
		if got := IsRef(s); got != want {
			t.Errorf("IsRef(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestStateStrings(t *testing.T) {
	if Present.String() != "present" || Absent.String() != "absent" || Locked.String() != "locked" {
		t.Fatalf("%v %v %v", Present, Absent, Locked)
	}
}

func TestPINErrorSaysTriesLeft(t *testing.T) {
	var err error = &PINError{Final: true}
	var pe *PINError
	if !errors.As(err, &pe) || !pe.Final {
		t.Fatal("errors.As lost the PINError")
	}
	if got := err.Error(); got == (&PINError{}).Error() {
		t.Fatalf("a final try reads like any refusal: %q", got)
	}
}
