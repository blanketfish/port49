package fence

import (
	"encoding/binary"
	"strings"
	"testing"
)

const (
	tUserObj  = 0x01
	tUser     = 0x02
	tGroupObj = 0x04
	tGroup    = 0x08
	tMask     = 0x10
	tOther    = 0x20
)

func aclBytes(version uint32, es ...aclEntry) []byte {
	b := binary.LittleEndian.AppendUint32(nil, version)
	for _, e := range es {
		b = binary.LittleEndian.AppendUint16(b, e.tag)
		b = binary.LittleEndian.AppendUint16(b, e.perm)
		b = binary.LittleEndian.AppendUint32(b, e.id)
	}
	return b
}

const none = 0xFFFFFFFF

func TestParsePOSIXACL(t *testing.T) {
	all := []aclEntry{{tUserObj, 6, none}, {tUser, 4, 1000}, {tGroupObj, 0, none}, {tGroup, 4, 77}, {tMask, 4, none}, {tOther, 0, none}}
	got, err := parsePOSIXACL(aclBytes(2, all...))
	if err != nil || len(got) != len(all) {
		t.Fatalf("every tag: %v %v", got, err)
	}
	for i := range all {
		if got[i] != all[i] {
			t.Errorf("entry %d: %v, want %v", i, got[i], all[i])
		}
	}
	for name, b := range map[string][]byte{
		"bad version":   aclBytes(1, all...),
		"empty":         nil,
		"short header":  {2, 0},
		"truncated":     aclBytes(2, all...)[:4+8*2+3],
		"unknown tag":   aclBytes(2, aclEntry{0x40, 4, 0}),
		"tag zero":      aclBytes(2, aclEntry{0, 4, 0}),
		"perm past rwx": aclBytes(2, aclEntry{tUser, 8, 5}),
	} {
		if es, err := parsePOSIXACL(b); err == nil {
			t.Errorf("%s: accepted, %v", name, es)
		}
	}
}

func TestTheSecretACLRule(t *testing.T) {
	const euid, ours, theirs = 1000, 50, 99
	groupOurs := func(g uint32) bool { return g == ours }
	base := func(extra ...aclEntry) []aclEntry {
		return append([]aclEntry{{tUserObj, 4, none}, {tGroupObj, 0, none}, {tMask, 4, none}, {tOther, 0, none}}, extra...)
	}
	for _, tc := range []struct {
		name  string
		es    []aclEntry
		group uint32
		want  string // "" accepted, else a substring of the refusal
	}{
		{"the systemd credential shape", base(aclEntry{tUser, 4, euid}), 0, ""},
		{"root named", base(aclEntry{tUser, 4, 0}), theirs, ""},
		{"our group named", base(aclEntry{tGroup, 4, ours}), theirs, ""},
		{"group_obj read, our owning group", []aclEntry{{tUserObj, 4, none}, {tGroupObj, 4, none}, {tMask, 4, none}, {tOther, 0, none}}, ours, ""},
		{"user other read", base(aclEntry{tUser, 4, 4242}), ours, "user:4242"},
		{"user other with nothing", base(aclEntry{tUser, 0, 4242}), ours, ""},
		{"group other read", base(aclEntry{tGroup, 4, theirs}), ours, "group:99"},
		{"group_obj read, foreign owning group", []aclEntry{{tUserObj, 4, none}, {tGroupObj, 4, none}, {tMask, 4, none}, {tOther, 0, none}}, theirs, "group::"},
		{"write to us by name", base(aclEntry{tUser, 6, euid}), ours, "write"},
		{"write to our group by name", base(aclEntry{tGroup, 2, ours}), ours, "write"},
		{"write to group_obj", []aclEntry{{tUserObj, 4, none}, {tGroupObj, 2, none}, {tMask, 4, none}, {tOther, 0, none}}, ours, "write"},
		{"other read", []aclEntry{{tUserObj, 4, none}, {tGroupObj, 0, none}, {tMask, 4, none}, {tOther, 4, none}}, ours, "other::"},
	} {
		err := secretACLRefusal(tc.es, euid, tc.group, groupOurs)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: refused: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "setfacl")):
			t.Errorf("%s: want a refusal naming %q with a setfacl hint, got %v", tc.name, tc.want, err)
		}
	}
}

func TestTheDirectoryACLRuleRefusesWriteOnly(t *testing.T) {
	const euid = 1000
	ok := []aclEntry{{tUserObj, 7, none}, {tUser, 5, euid}, {tUser, 5, 4242}, {tGroupObj, 5, none}, {tMask, 5, none}, {tOther, 0, none}}
	if err := dirACLRefusal(ok, euid); err != nil {
		t.Errorf("a read/search ACL refused: %v", err)
	}
	for name, e := range map[string]aclEntry{
		"user other":  {tUser, 2, 4242},
		"group other": {tGroup, 2, 99},
		"group_obj":   {tGroupObj, 2, none},
		"other":       {tOther, 2, none},
	} {
		es := append([]aclEntry{{tUserObj, 7, none}, {tMask, 7, none}}, e)
		if err := dirACLRefusal(es, euid); err == nil || !strings.Contains(err.Error(), "setfacl") {
			t.Errorf("%s write: %v", name, err)
		}
	}
}

func TestTheBaseEntryFixesNameTheModifyForm(t *testing.T) {
	groupOurs := func(g uint32) bool { return g == 50 }
	for name, tc := range map[string]struct {
		es   []aclEntry
		want string
	}{
		"group::": {[]aclEntry{{tUserObj, 4, none}, {tGroupObj, 4, none}, {tMask, 4, none}, {tOther, 0, none}}, "setfacl -m g::-"},
		"other::": {[]aclEntry{{tUserObj, 4, none}, {tGroupObj, 0, none}, {tMask, 4, none}, {tOther, 4, none}}, "setfacl -m o::-"},
		"user:":   {[]aclEntry{{tUserObj, 4, none}, {tGroupObj, 0, none}, {tUser, 4, 4242}, {tMask, 4, none}, {tOther, 0, none}}, "setfacl -x u:4242"},
	} {
		err := secretACLRefusal(tc.es, 1000, 99, groupOurs)
		if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "-x g::") || strings.Contains(err.Error(), "-x o::") {
			t.Errorf("%s: want the fix %q, got %v", name, tc.want, err)
		}
	}
	err := dirACLRefusal([]aclEntry{{tUserObj, 7, none}, {tGroupObj, 2, none}, {tMask, 7, none}, {tOther, 2, none}}, 1000)
	if err == nil || !strings.Contains(err.Error(), "setfacl -m g::-") {
		t.Errorf("directory group::: %v", err)
	}
	err = dirACLRefusal([]aclEntry{{tUserObj, 7, none}, {tGroupObj, 0, none}, {tMask, 7, none}, {tOther, 2, none}}, 1000)
	if err == nil || !strings.Contains(err.Error(), "setfacl -m o::-") {
		t.Errorf("directory other::: %v", err)
	}
}

func TestAnACLMissingARequiredEntryIsRefused(t *testing.T) {
	for name, es := range map[string][]aclEntry{
		"empty":               nil,
		"no user::":           {{tGroupObj, 0, none}, {tOther, 0, none}},
		"no group::":          {{tUserObj, 4, none}, {tOther, 0, none}},
		"no other::":          {{tUserObj, 4, none}, {tGroupObj, 0, none}},
		"named but no mask::": {{tUserObj, 4, none}, {tUser, 4, 1}, {tGroupObj, 0, none}, {tOther, 0, none}},
		"two other::":         {{tUserObj, 4, none}, {tGroupObj, 0, none}, {tOther, 0, none}, {tOther, 4, none}},
	} {
		if got, err := parsePOSIXACL(aclBytes(2, es...)); err == nil {
			t.Errorf("%s: accepted, %v", name, got)
		}
	}
	// the bare three-entry ACL (a plain mode) needs no mask
	if _, err := parsePOSIXACL(aclBytes(2, aclEntry{tUserObj, 4, none}, aclEntry{tGroupObj, 0, none}, aclEntry{tOther, 0, none})); err != nil {
		t.Errorf("the three base entries: %v", err)
	}
}

func TestFetchACLSurvivesAnUnstableSize(t *testing.T) {
	calls := 0
	get := func(dest []byte) (int, error) {
		calls++
		if calls == 1 {
			return 0, nil // a size query says empty ...
		}
		return 12, nil // ... and the next call, given a zero-length dest, says otherwise
	}
	if _, _, err := fetchACL(get); err == nil {
		t.Error("an unstable size was accepted")
	}
	if _, _, err := fetchACL(func(dest []byte) (int, error) { return 0, nil }); err == nil {
		t.Error("an empty ACL xattr was accepted")
	}
}
