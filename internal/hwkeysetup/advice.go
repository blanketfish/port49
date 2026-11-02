package hwkeysetup

import "fmt"

// Advice is the ykman commands that fix what Report found wrong, empty when it
// is ready. ykman, not port49, asks for the PIV management key, so no line
// names one; none names a serial, PIN or PUK. sessionSlot is 9a, or 9e for a
// site that keeps the session key there.
//
// A slot libykcs11 shows as empty may hold a key with no certificate in it
// (unmeasured: L91 cell c), and generating over a key replaces it. So a missing
// slot's line is followed by the certificate line for that case.
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
	cert := func(slot string) {
		out = append(out, fmt.Sprintf("# if %s already holds a key, add its certificate instead of generating:", slot),
			fmt.Sprintf("ykman piv certificates generate --subject \"CN=port49 %s\" %s port49-%s.pub.pem", slot, slot, slot))
	}
	if r.Failed(CheckSessionSlot) {
		gen(sessionSlot, "NEVER")
		cert(sessionSlot)
	}
	if r.Failed(CheckTouchSlot) {
		gen("9c", "ALWAYS")
		cert("9c")
	} else if r.Failed(CheckTouchPolicy) {
		out = append(out, "# 9c was not made with touch policy always; this replaces its key:")
		gen("9c", "ALWAYS")
	}
	return out
}
