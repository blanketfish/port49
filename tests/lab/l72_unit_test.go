package lab

import "testing"

// Every L72 cell named in spec §15 has a runner, and none is run twice.
func TestL72CellsAreTheRegistersCells(t *testing.T) {
	want := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o"}
	got := map[string]bool{}
	for _, c := range l72Cells {
		if got[c.id] {
			t.Fatalf("cell %s twice", c.id)
		}
		got[c.id] = true
	}
	for _, id := range want {
		if !got[id] {
			t.Errorf("cell %s has no runner", id)
		}
	}
}

func TestL72ParsesTheClientsLine(t *testing.T) {
	r, err := parseL72Result([]byte(`{"conn":1,"handshake":"error","error":"remote error: tls: bad certificate","resumed":false,"status":"none","flags":0,"after":"","closed_ms":0}` + "\n"))
	if err != nil || len(r) != 1 || r[0].Error != "remote error: tls: bad certificate" {
		t.Fatalf("%+v %v", r, err)
	}
}
