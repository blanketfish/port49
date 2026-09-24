package broker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/store/memory"
)

// A blob whose rule text carries a value the redaction patterns hide is
// logged with that value redacted and says so; the store keeps the blob
// verbatim, as the policy file does (spec §5.8). A blob with nothing to hide
// is logged byte for byte.
func TestABlobEventNeverCarriesARuleSecret(t *testing.T) {
	put := func(b *Broker, rules ...engine.Rule) (string, []byte) {
		body, hash, err := engine.Encode(engine.Blob{Bundle: "sha256:policy", Platform: "arista_eos",
			Normalize: engine.Normalize{PipeToken: "|"}, Privilege: "admin", Rules: rules})
		if err != nil {
			t.Fatal(err)
		}
		if err := b.putBlob(context.Background(), hash, body); err != nil {
			t.Fatal(err)
		}
		return hash, body
	}
	var log bytes.Buffer
	st := memory.New(time.Now)
	b := &Broker{Store: st, Log: decision.NewJSONLines(&log), Now: time.Now, MaxSessionAge: time.Hour}
	hash, body := put(b, engine.Rule{Verdict: engine.Deny, Rule: "snmp-server community Hunter2 **", Role: "no_public"},
		engine.Rule{Verdict: engine.Permit, Rule: "**", Role: "admin"})
	if strings.Contains(log.String(), "Hunter2") || !strings.Contains(log.String(), `"redacted":true`) ||
		!strings.Contains(log.String(), "snmp-server community "+platform.Redacted+" **") ||
		!strings.Contains(log.String(), hash) {
		t.Fatalf("the blob event: %s", log.String())
	}
	if stored, err := st.GetBlob(context.Background(), hash); err != nil || !bytes.Equal(stored, body) {
		t.Fatalf("the store keeps the blob verbatim: %s %v", stored, err)
	}

	log.Reset()
	b.Redact = func(string) []platform.Redaction { return nil }
	_, body = put(b, engine.Rule{Verdict: engine.Deny, Rule: "snmp-server community Other **", Role: "no_public"})
	if !strings.Contains(log.String(), string(body)) || strings.Contains(log.String(), "redacted") {
		t.Fatalf("nothing to hide, logged verbatim: %s", log.String())
	}
}

// A broker line that names policy content — a resolve or compile error
// quotes the rule it failed on — is redacted before the process log gets it
// (task 11 review C2).
func TestABrokerLogLineNeverQuotesARuleSecret(t *testing.T) {
	var out bytes.Buffer
	defer func(w io.Writer) { log.SetOutput(w) }(log.Writer())
	log.SetOutput(&out)
	(&Broker{}).logf("broker: resolving %s on %q: %v", "user:a", "leaf1",
		fmt.Errorf("rule %q: bad", "snmp-server community Hunter2 ro"))
	if strings.Contains(out.String(), "Hunter2") || !strings.Contains(out.String(), "snmp-server community") {
		t.Fatalf("%s", out.String())
	}
}
