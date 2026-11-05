//go:build hwkey_dlopen

package pkcs11

import "github.com/blanketfish/port49/internal/hwkey/serialmask"

// Tokens lists the tokens the module at modulePath shows, in slot order. It is
// read-only: it takes the module through Load, which keeps one initialized
// Module per path for the process, and asks C_GetSlotList(tokenPresent) and
// C_GetTokenInfo. It opens no session, never calls C_Login and never asks for a
// PIN. It never calls C_Finalize either: that would tear down the cached module
// under the next Open in the same process.
func Tokens(modulePath string) ([]Token, error) {
	m, err := Load(modulePath)
	if err != nil {
		return nil, err
	}
	slots, err := m.slotList()
	if err != nil {
		return nil, err
	}
	var out []Token
	for _, slot := range slots {
		ti, err := m.tokenInfo(slot)
		if err != nil {
			continue // a token pulled between the two calls
		}
		t := Token{Slot: slot, Label: trimField(ti.label[:]), Model: trimField(ti.model[:])}
		t.MaskedLabel = serialmask.MaskSerial(t.Label)
		if trimField(ti.serial[:]) != "" {
			t.MaskedSerial = "<serial>"
		}
		out = append(out, t)
	}
	return out, nil
}
