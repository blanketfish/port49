package lab

import "testing"

// Cell (a) agrees only when the listed spelling is accepted with no record,
// the unlisted one makes one record naming what openssl sent, and the next
// connection is declined at Accept, not held.
func TestL81GradesCellA(t *testing.T) {
	good := l81Obs{acceptedOK: 1, refused: 1, refusedDetail: true, declinedRise: 1}
	if !l81AgreesA(good) {
		t.Fatal("the agreeing run did not agree")
	}
	for name, o := range map[string]l81Obs{
		"the listed spelling refused":   {acceptedOK: 0, acceptedRecords: 1, refused: 1, refusedDetail: true, declinedRise: 1},
		"a second record":               {acceptedOK: 1, refused: 2, refusedDetail: true, declinedRise: 0},
		"struck":                        {acceptedOK: 1, refused: 1, refusedDetail: true, heldRise: 1},
		"the SNI was not what was sent": {acceptedOK: 1, refused: 1, declinedRise: 1},
	} {
		if l81AgreesA(o) {
			t.Errorf("%s: agreed", name)
		}
	}
}
