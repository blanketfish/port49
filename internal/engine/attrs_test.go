package engine

import "testing"

func TestGrantedPrivLvl(t *testing.T) {
	for _, tt := range []struct {
		attrs []string
		want  uint8
		ok    bool
	}{
		{nil, 0, false},
		{[]string{"shell:roles*network-admin"}, 0, false},
		{[]string{"priv-lvl=15"}, 15, true},
		{[]string{"priv-lvl*15"}, 15, true}, // the optional form a device reads just the same
		{[]string{"priv-lvl=0"}, 0, true},
		{[]string{"shell:roles*network-admin", "priv-lvl=1"}, 1, true},
		// Not a level, so not a grant: the context keeps what it had rather
		// than being moved to something the reply did not say.
		{[]string{"priv-lvl="}, 0, false},
		{[]string{"priv-lvl=fifteen"}, 0, false},
		{[]string{"priv-lvl=16"}, 0, false},
		{[]string{"priv-lvl=-1"}, 0, false},
		{[]string{"priv-lvl=300"}, 0, false},
		{[]string{"priv-lvlx=15"}, 0, false},
		// The last one wins, as it does on a device reading them in order.
		{[]string{"priv-lvl=1", "priv-lvl=15"}, 15, true},
	} {
		got, _, ok := GrantedPrivLvl(tt.attrs)
		if got != tt.want || ok != tt.ok {
			t.Errorf("GrantedPrivLvl(%q) = %d, %v; want %d, %v", tt.attrs, got, ok, tt.want, tt.ok)
		}
	}
}

// The index names the attribute that decided, so a report can say where it
// came from.
func TestGrantedPrivLvlNamesTheAttribute(t *testing.T) {
	if _, at, ok := GrantedPrivLvl([]string{"priv-lvl=1", "idletime*5", "priv-lvl*15", "priv-lvl=x"}); !ok || at != 2 {
		t.Fatalf("at %d, ok %v", at, ok)
	}
	if _, at, ok := GrantedPrivLvl(nil); ok || at != -1 {
		t.Fatalf("at %d, ok %v", at, ok)
	}
}

// SplitName reads a word as IOS-XE sends an interface name: a name of
// letters (and `-`) and an index, or not at all (L21).
func TestSplitName(t *testing.T) {
	for word, want := range map[string][2]string{
		"GigabitEthernet1": {"GigabitEthernet", "1"}, "Gi1/0/1": {"Gi", "1/0/1"}, "Port-channel10": {"Port-channel", "10"},
		"Loopback0.5": {"Loopback", "0.5"}, "1": {}, "GigabitEthernet": {}, "p49-l21": {}, "x1y": {}, "": {},
	} {
		head, index, ok := SplitName(word)
		if ok != (want[0] != "") || head != want[0] || index != want[1] {
			t.Errorf("SplitName(%q) = %q %q %v", word, head, index, ok)
		}
	}
}
