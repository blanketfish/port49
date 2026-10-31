package helm

import (
	"io/fs"
	"testing"
)

// kubeletWalks is the kubelet's own test for whether fsGroup makes it walk a volume with
// fsGroupChangePolicy OnRootMismatch: pkg/volume/volume_linux.go at v1.33.1, requiresPermissionChange
// (lines 192-233). It skips the walk only when all hold: the root's gid is the fsGroup; the root is a
// directory whose permission bits include 0770 (0440 and 0110 on a read-only mount); and the root
// has setgid. Any other root is walked: every entry is chowned to the fsGroup, every file's mode
// is ORed with 0660 and every directory's with 2770 (changeFilePermission, lines 149-182). The walk only
// adds bits, so a data directory it reaches is left group-writable. gid is the root's group id as text.
func kubeletWalks(gid, fsGroup string, mode fs.FileMode, readOnly bool) bool {
	if gid != fsGroup || !mode.IsDir() || mode&fs.ModeSetgid == 0 {
		return true
	}
	want := fs.FileMode(0o770)
	if readOnly {
		want = 0o550 // 0440 and 0110
	}
	return mode.Perm()&want != want
}

// The root the chart's init container makes (root:65532 3770) is one the kubelet skips; the first
// design's (g-w, 2755) is one it walks at the next pod's start, which is what crash-looped the broker.
func TestTheKubeletRuleSaysWhyTheRootIs3770(t *testing.T) {
	for _, tc := range []struct {
		name  string
		gid   string
		mode  fs.FileMode
		walks bool
	}{
		{"3770 root:65532, the chart's root", "65532", fs.ModeDir | fs.ModeSetgid | fs.ModeSticky | 0o770, false},
		{"2775, as the kubelet leaves a fresh volume", "65532", fs.ModeDir | fs.ModeSetgid | 0o775, false},
		{"2755, the group write bit removed", "65532", fs.ModeDir | fs.ModeSetgid | 0o755, true},
		{"0770 without setgid", "65532", fs.ModeDir | 0o770, true},
		{"3770 but group 0", "0", fs.ModeDir | fs.ModeSetgid | fs.ModeSticky | 0o770, true},
		{"a fresh volume, root:root 0755", "0", fs.ModeDir | 0o755, true},
	} {
		if got := kubeletWalks(tc.gid, "65532", tc.mode, false); got != tc.walks {
			t.Errorf("%s: kubeletWalks = %v, want %v", tc.name, got, tc.walks)
		}
	}
}
