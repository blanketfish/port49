package ci

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// test.yml is the workflow that runs the whole suite, so it is held to the CI
// rules: every action pinned by a full commit SHA with its version in a comment,
// no persisted checkout credentials, an explicit least-privilege permissions
// block on every job, and the port49d shards followed by the check that they
// cover every test.
func TestTheTestWorkflowFollowsTheCIRules(t *testing.T) {
	raw, err := os.ReadFile("../../.github/workflows/test.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	pinned := regexp.MustCompile(`uses: [\w./-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$`)
	var checkouts, jobs int
	for _, line := range strings.Split(text, "\n") {
		trim := strings.TrimSpace(line)
		if strings.Contains(trim, "uses:") && !pinned.MatchString(trim) {
			t.Errorf("an action not pinned by SHA with a version comment: %s", trim)
		}
		if strings.Contains(trim, "actions/checkout@") {
			checkouts++
		}
	}
	if n := strings.Count(text, "persist-credentials: false"); n != checkouts {
		t.Errorf("%d checkouts, %d with persist-credentials: false", checkouts, n)
	}
	jobs = len(regexp.MustCompile(`(?m)^  [a-z0-9]+:\n    runs-on:`).FindAllString(text, -1))
	if n := strings.Count(text, "    permissions: {contents: read}"); n != jobs || jobs == 0 {
		t.Errorf("%d jobs, %d with their own permissions block", jobs, n)
	}
	for _, want := range []string{"testshard -pkg ./internal/port49d -check -n 3", "make test-shard SHARD=${{ matrix.shard }}",
		`shard: ["1/3", "2/3", "3/3"]`, "make test-root", "make test-rest"} {
		if !strings.Contains(text, want) {
			t.Errorf("test.yml lacks %q", want)
		}
	}
	if strings.Contains(text, "secrets.") {
		t.Error("test.yml reads a secret")
	}
}
