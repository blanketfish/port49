package devicecert

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestClassify(t *testing.T) {
	for msg, want := range map[string]Outcome{
		"tls: client sent unexpected early data":               EarlyDataRefused,
		"tls: client didn't provide a certificate":             NoClientCertificate,
		"tls: client offered only unsupported versions: [303]": VersionRefused,
		"tls: invalid signature by the client certificate":     HandshakeFailed,
		"EOF": HandshakeFailed,
	} {
		if got := Classify(errors.New(msg), false); got != want {
			t.Errorf("%q: %s, want %s", msg, got, want)
		}
	}
	if got := Classify(fmt.Errorf("x: %w", context.DeadlineExceeded), false); got != HandshakeTimeout {
		t.Errorf("deadline: %s", got)
	}
	if got := Classify(errors.New("read: connection reset"), true); got != HandshakeTimeout {
		t.Errorf("timed out: %s", got)
	}
}

func TestOnlyStatusUnavailableIsNotStruck(t *testing.T) {
	for _, o := range Outcomes {
		if o.Struck() == (o == StatusUnavailable) {
			t.Errorf("%s: Struck %v", o, o.Struck())
		}
	}
	if OK.Struck() || Resumed.Struck() {
		t.Error("a success is struck")
	}
	if len(Outcomes) != 12 {
		t.Fatalf("%d refusal outcomes, want spec §10's 12", len(Outcomes))
	}
}
