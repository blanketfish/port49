//go:build hwkey && hwkey_dlopen

package pkcs11

import "time"

// FakeSign has every Sign on s answer C_Sign with rv after took of fake time,
// without calling the token, and returns how many C_Sign calls it has made
// and the func that removes the fake. The clock is s's own, so no test sleeps.
func FakeSign(s *Signer, rv uint, took time.Duration) (calls func() int, restore func()) {
	return FakeSignAs(s, "C_Sign", rv, took)
}

// FakeSignAs is FakeSign with the module function that fails named: "C_Sign"
// or "C_SignInit".
func FakeSignAs(s *Signer, fn string, rv uint, took time.Duration) (calls func() int, restore func()) {
	var n int
	var elapsed time.Duration
	base := time.Unix(1_700_000_000, 0)
	s.mu.Lock()
	s.now = func() time.Time { return base.Add(elapsed) }
	s.mu.Unlock()
	signFault = func(*Signer) (string, uint) {
		n++
		elapsed += took
		return fn, rv
	}
	return func() int { return n }, func() {
		signFault = nil
		s.mu.Lock()
		s.now = nil
		s.mu.Unlock()
	}
}

// RVUserNotLoggedIn is CKR_USER_NOT_LOGGED_IN.
const RVUserNotLoggedIn = ckrUserNotLoggedIn
