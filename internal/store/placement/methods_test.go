package placement

import (
	"reflect"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/store"
)

// Every store.Store method is placed by decision, not by embedding: a new
// method fails TestEveryStoreMethodIsPlaced until it is listed in one table
// (decision 51).
var directoryMethods = set(`
	PutRevocation GetRevocation DeleteRevocation ListRevocations GetLift
	PutMembership PutPin RefuseMapKeys GetMembership MembershipByKey DeleteMembership
	PutLogout GetLogout
`)

var sessionMethods = set(`
	PutToken Candidates TokenIDs RedeemAndReceipt DeleteTokens DeleteToken PurgeTokens PurgeOnceRecords
	GetReceipt ExtendReceipt FailReceipt DeleteReceiptsByPrincipal
	PutContext GetContext SwapContext SwapLogin RewriteContext TouchContext SetPrivilege
	AnnotateContext RefreshContext SetRevokedAt SetContextPolicy StampRefreshed
	DeleteContext DeleteContextIf PutBlob GetBlob BumpBlob
	IndexContext UnindexContext UnindexRef ContextsByPrincipal ContextsBySid ContextsByCert
	ReindexSid ActivePrincipals TokensByPrincipal TokensByCert
	ReserveIdempotency CompleteIdempotency ReleaseIdempotency
	SupersedeTokens SupersedeAll SupersededAt
	PutOnce TakeOnce PutOIDCOwner OIDCOwner PutMFAProof GetMFAProof
	NoteSignInAttempt UndoSignInAttempt ClearSignInAttempts
	MembershipPrincipals MembershipSeals
`)

func set(names string) map[string]bool {
	m := map[string]bool{}
	for _, n := range strings.Fields(names) {
		m[n] = true
	}
	return m
}

func TestEveryStoreMethodIsPlaced(t *testing.T) {
	st := reflect.TypeOf((*store.Store)(nil)).Elem()
	for i := 0; i < st.NumMethod(); i++ {
		n := st.Method(i).Name
		places := 0
		for _, tbl := range []map[string]bool{directoryMethods, sessionMethods} {
			if tbl[n] {
				places++
			}
		}
		if places != 1 {
			t.Errorf("store.Store.%s is in %d placement tables, want exactly one; place it", n, places)
		}
	}
	for _, tbl := range []map[string]bool{directoryMethods, sessionMethods} {
		for n := range tbl {
			if _, ok := st.MethodByName(n); !ok {
				t.Errorf("the table names %s, which store.Store lacks", n)
			}
		}
	}
}
