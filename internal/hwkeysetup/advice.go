package hwkeysetup

import "fmt"

// Advice is the ykman commands that fix what Report found wrong, empty when it
// is ready. ykman, not port49, asks for the PIV management key, so no line
// names one; none names a serial, PIN or PUK. sessionSlot is 9a, or 9e for a
// site that keeps the session key there.
//
// A slot libykcs11 shows as empty may hold a key with no certificate in it
// (unmeasured: L91 cell c), and generating over a key replaces it. So a missing
// slot's generate line follows the certificate line for that case, never leads it.
func Advice(r Report, sessionSlot string) []string {
	if r.Ready {
		return nil
	}
	if sessionSlot == "" {
		sessionSlot = "9a"
	}
	var out []string
	gen := func(slot, touch string) {
		out = append(out, fmt.Sprintf("ykman piv keys generate --algorithm ECCP256 --pin-policy ONCE --touch-policy %s %s port49-%s.pub.pem",
			touch, slot, slot))
	}
	// missing is a slot libykcs11 lists no key in: the certificate line comes first, because the
	// generate line replaces any key the slot holds.
	missing := func(slot, touch string) {
		out = append(out, fmt.Sprintf("# if %s already holds a key, add its certificate (this replaces nothing):", slot),
			fmt.Sprintf("ykman piv certificates generate --subject \"CN=port49 %s\" %s port49-%s.pub.pem", slot, slot, slot),
			fmt.Sprintf("# only if %s holds no key, make one (this replaces any key already there):", slot))
		gen(slot, touch)
	}
	if r.Failed(CheckSessionSlot) {
		missing(sessionSlot, "NEVER")
	}
	if r.Failed(CheckTouchSlot) {
		missing("9c", "ALWAYS")
	} else if r.Failed(CheckTouchPolicy) {
		out = append(out, "# 9c was not made with touch policy always; this replaces its key:")
		gen("9c", "ALWAYS")
	}
	return out
}
