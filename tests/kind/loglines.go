package kind

import (
	"regexp"
	"strings"
)

// What a successful enrollments export may log (enrollments_test.go): untagged, so `make test` runs its unit test.

// prefixTag is the `--prefix` tag kubectl puts on each log line: [pod/<name>/<container>].
var prefixTag = regexp.MustCompile(`(?m)^\[pod/[^\]]+\] ?`)

// certWarning is the one line a successful export may log: the product's warning that the broker's etcd
// certificate is near its end (the stack's certificates last a day). Anchored, and its date has no characters
// a credential would need.
var certWarning = regexp.MustCompile(`^port49-broker: directory store: the broker's etcd certificate \(CN=port49-broker\) is valid until \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z \(\d+ days?\)$`)

// unexpectedLines is the lines of a log, tags off, that are not certWarning, joined; "" when there are none.
func unexpectedLines(log string) string {
	var extra []string
	for _, ln := range strings.Split(prefixTag.ReplaceAllString(log, ""), "\n") {
		if ln = strings.TrimSpace(ln); ln != "" && !certWarning.MatchString(ln) {
			extra = append(extra, ln)
		}
	}
	return strings.Join(extra, "\n")
}

// logLines is a log with its prefix tags taken off and its white space trimmed.
func logLines(log string) string { return strings.TrimSpace(prefixTag.ReplaceAllString(log, "")) }
