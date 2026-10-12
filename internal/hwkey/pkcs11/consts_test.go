package pkcs11

import "testing"

// The function-list indexes follow the PKCS#11 v2.40 header's order
// (CK_FUNCTION_LIST in pkcs11f.h); one wrong index calls another function.
func TestFunctionIndexes(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"C_Initialize", fnInitialize, 0},
		{"C_Finalize", fnFinalize, 1},
		{"C_GetSlotList", fnGetSlotList, 4},
		{"C_GetTokenInfo", fnGetTokenInfo, 6},
		{"C_OpenSession", fnOpenSession, 12},
		{"C_CloseSession", fnCloseSession, 13},
		{"C_Login", fnLogin, 18},
		{"C_Logout", fnLogout, 19},
		{"C_GetAttributeValue", fnGetAttributeValue, 24},
		{"C_FindObjectsInit", fnFindObjectsInit, 26},
		{"C_FindObjects", fnFindObjects, 27},
		{"C_FindObjectsFinal", fnFindObjectsFinal, 28},
		{"C_SignInit", fnSignInit, 42},
		{"C_Sign", fnSign, 43},
		{"C_GenerateKeyPair", fnGenerateKeyPair, 59},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}
