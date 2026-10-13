//go:build hwkey_dlopen

package pkcs11

// PINBlocked is whether the token says its user PIN is blocked
// (CKF_USER_PIN_LOCKED): no PIN is taken until the token's own unblock
// procedure (its PUK) has run. False when the token cannot be asked. It
// satisfies hwkey.Blocker, so a refused PIN is reported as a blocked one
// whether the token answered CKR_PIN_LOCKED or the try that failed was the
// last.
func (s *Signer) PINBlocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	ti, err := s.m.tokenInfo(s.slot)
	return err == nil && ti.flags&ckfUserPINLocked != 0
}
