package kind

import "testing"

func TestUnexpectedLinesAllowsOnlyTheCertificateWarning(t *testing.T) {
	const warn = "port49-broker: directory store: the broker's etcd certificate (CN=port49-broker) is valid until 2026-11-05T17:40:00Z (0 days)"
	for _, c := range []struct{ name, log, want string }{
		{"the real line, tagged", "[pod/x/export] " + warn + "\n", ""},
		{"the real line twice", warn + "\n" + warn + "\n", ""},
		{"nothing", "", ""},
		{"a different line", "[pod/x/export] " + warn + "\nbroker: exported 3 records\n", "broker: exported 3 records"},
		{"a credential word", "[pod/x/export] " + warn + "\nthe password is hunter2\n", "the password is hunter2"},
		{"the line with a credential word in its date", "port49-broker: directory store: the broker's etcd certificate (CN=port49-broker) is valid until password=x (0 days)", "port49-broker: directory store: the broker's etcd certificate (CN=port49-broker) is valid until password=x (0 days)"},
	} {
		if got := unexpectedLines(c.log); got != c.want {
			t.Errorf("%s: unexpected %q, want %q", c.name, got, c.want)
		}
	}
}
