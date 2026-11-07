package docgen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/devicecert"
)

const (
	specPath        = "docs/design/2026-08-23-policy-engine-spec.md"
	decisionLogDesc = "internal/docgen/descriptions/decision_log.yaml"
	reasonPage      = "docs/site/reference/reason-codes.md"
	decisionLogPage = "docs/site/reference/decision-log.md"
	tlsOutcomeKey   = "tls_outcome."
)

// SpecTable is the first pipe table after the line equal to heading, without its header and rule rows.
// A cell is trimmed but otherwise as the spec writes it; an escaped pipe stays escaped.
func SpecTable(spec []byte, heading string) ([][]string, error) {
	lines := strings.Split(string(spec), "\n")
	i := 0
	for ; i < len(lines); i++ {
		if strings.TrimRight(lines[i], " \t\r") == heading {
			break
		}
	}
	if i == len(lines) {
		return nil, fmt.Errorf("spec has no heading %q", heading)
	}
	for i++; i < len(lines) && !strings.HasPrefix(lines[i], "|"); i++ {
		if strings.HasPrefix(lines[i], "#") {
			return nil, fmt.Errorf("spec has no table under %q", heading)
		}
	}
	var rows [][]string
	for ; i < len(lines) && strings.HasPrefix(lines[i], "|"); i++ {
		rows = append(rows, splitRow(lines[i]))
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("spec has no table under %q", heading)
	}
	return rows[2:], nil
}

// splitRow splits a table row at its unescaped pipes.
func splitRow(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimSuffix(strings.TrimPrefix(line, "|"), "|")
	var cells []string
	var cur strings.Builder
	for i := 0; i < len(line); i++ {
		switch {
		case line[i] == '\\' && i+1 < len(line) && line[i+1] == '|':
			cur.WriteString(`\|`)
			i++
		case line[i] == '|':
			cells = append(cells, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(line[i])
		}
	}
	return append(cells, strings.TrimSpace(cur.String()))
}

// ReasonPage is the reference page for the closed reason vocabulary: one row per decision.Reasons(), in
// declared order, with the meaning spec §5.7's table gives it. It fails, naming them all, on a code with no
// spec row and a spec row with no code.
func ReasonPage(spec []byte) (string, error) {
	rows, err := SpecTable(spec, "#### Reason codes")
	if err != nil {
		return "", err
	}
	meaning := map[string]string{}
	var order []string
	for _, r := range rows {
		if len(r) < 2 {
			return "", fmt.Errorf("a reason row of the spec has %d cells, want 2: %q", len(r), r)
		}
		c := strings.Trim(r[0], "` ")
		meaning[c] = r[1]
		order = append(order, c)
	}
	var problems []string
	known := map[string]bool{}
	for _, r := range decision.Reasons() {
		known[string(r)] = true
		if _, ok := meaning[string(r)]; !ok {
			problems = append(problems, "no spec row for code "+string(r))
		}
	}
	for _, c := range order {
		if !known[c] {
			problems = append(problems, "no code for spec row "+c)
		}
	}
	if len(problems) > 0 {
		return "", fmt.Errorf("reason codes: %s", strings.Join(problems, "; "))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "---\ntitle: Reason codes\ndescription: %s\n---\n\n%s\n\n# Reason codes\n\n"+
		"The `reason` of a decision record is one of the codes below, and nothing else. The list is closed, "+
		"so a denial can be counted and alerted on without parsing prose. The metrics use the same codes. "+
		"The codes are in the order the server declares them.\n\n"+
		"| Reason | Meaning |\n|---|---|\n",
		jsonString("The closed list of reason codes a decision can carry, and what each means."), Header)
	for _, r := range decision.Reasons() {
		fmt.Fprintf(&b, "| `%s` | %s |\n", r, meaning[string(r)])
	}
	return b.String(), nil
}

// LoadDecisionLogDescriptions reads the decision log's descriptions file under root.
func LoadDecisionLogDescriptions(root string) (map[string]string, error) {
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(decisionLogDesc)))
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	if err := yaml.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("%s: %w", decisionLogDesc, err)
	}
	return out, nil
}

// Field is one JSON field of the decision record. Path is dotted: a map key is <name> and a list item is [].
type Field struct{ Path, Type string }

// RecordFields lists the JSON fields of decision.Record, recursive, in declared order.
func RecordFields() []Field {
	var out []Field
	walkJSON(reflect.TypeOf(decision.Record{}), "", map[reflect.Type]bool{}, &out)
	return out
}

var rawMessageType = reflect.TypeOf(json.RawMessage{})

func walkJSON(t reflect.Type, path string, active map[reflect.Type]bool, out *[]Field) {
	t = deref(t)
	switch {
	case path != "" && t == rawMessageType:
		*out = append(*out, Field{path, "object"})
		return
	case path != "" && isLeaf(t):
		*out = append(*out, Field{path, leafLabel(path, t)})
		return
	}
	switch t.Kind() {
	case reflect.Struct:
		if active[t] {
			return
		}
		active[t] = true
		defer delete(active, t)
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			walkJSON(f.Type, join(path, name), active, out)
		}
	case reflect.Map:
		if e := deref(t.Elem()); e.Kind() == reflect.Struct && !isLeaf(e) {
			walkJSON(e, path+".<name>", active, out)
			return
		}
		*out = append(*out, Field{path, typeLabel(path, t)})
	case reflect.Slice, reflect.Array:
		if e := deref(t.Elem()); e.Kind() == reflect.Struct && !isLeaf(e) {
			walkJSON(e, path+".[]", active, out)
			return
		}
		*out = append(*out, Field{path, typeLabel(path, t)})
	default:
		*out = append(*out, Field{path, typeLabel(path, t)})
	}
}

// tlsOutcomes is every tls_outcome value: the two that admit a handshake, then every refusal.
func tlsOutcomes() []devicecert.Outcome {
	return append([]devicecert.Outcome{devicecert.OK, devicecert.Resumed}, devicecert.Outcomes...)
}

// DecisionLogPage is the reference page for the decision log: the events table of spec §5.7, every field of
// the record with its type and description, and the tls_outcome vocabulary. It fails, naming them all, if a
// field or an outcome has no description, a description has no field, or an entry is still a DRAFT.
func DecisionLogPage(spec []byte, desc map[string]string) (string, error) {
	events, err := SpecTable(spec, "#### Events")
	if err != nil {
		return "", err
	}
	fields := RecordFields()
	have := map[string]bool{descDescription: true, descIntro: true}
	var problems []string
	check := func(key string) {
		have[key] = true
		d := strings.TrimSpace(desc[key])
		switch {
		case d == "":
			problems = append(problems, "no description for "+key)
		case strings.HasPrefix(d, draftPrefix):
			problems = append(problems, key+" is still a DRAFT")
		}
	}
	for _, k := range []string{descDescription, descIntro} {
		check(k)
	}
	for _, f := range fields {
		check(f.Path)
	}
	for _, o := range tlsOutcomes() {
		check(tlsOutcomeKey + string(o))
	}
	var extra []string
	for k := range desc {
		if !have[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		problems = append(problems, "no field for description "+k)
	}
	for _, r := range events {
		if len(r) < 3 {
			problems = append(problems, fmt.Sprintf("an events row of the spec has %d cells, want 3", len(r)))
		}
	}
	if len(problems) > 0 {
		return "", fmt.Errorf("%s: %s", decisionLogDesc, strings.Join(problems, "; "))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "---\ntitle: Decision log\ndescription: %s\n---\n\n%s\n\n# Decision log\n\n%s\n",
		jsonString(oneLine(desc[descDescription])), Header, strings.TrimSpace(desc[descIntro]))

	b.WriteString("\n## Events\n\n| Event | Emitted by | What it decides |\n|---|---|---|\n")
	for _, r := range events {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", r[0], r[1], r[2])
	}

	b.WriteString("\n## Fields\n\n| Field | Type | Description |\n|---|---|---|\n")
	for _, f := range fields {
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", f.Path, f.Type, cell(desc[f.Path]))
	}

	b.WriteString("\n## The tls_outcome values {#tls_outcome}\n\n" +
		"A record from the RFC 9887 (TACACS+ over TLS) listener carries `transport: \"tls\"`. A `tls_refused` " +
		"record carries the `tls_outcome` that says why the handshake was refused. " +
		"The handshake counter `port49_tls_handshakes_total` uses the same values as its `outcome` label. " +
		"Strike says whether the refusal counts against the source address, as a wrong key does.\n\n" +
		"| `tls_outcome` | Means | Strike |\n|---|---|---|\n")
	for _, o := range tlsOutcomes() {
		strike := "no"
		if o.Struck() {
			strike = "yes"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", o, cell(desc[tlsOutcomeKey+string(o)]), strike)
	}

	b.WriteString("\n## packet_fields\n\n" +
		"A record for a validated request carries `packet_fields`: the request's header fields as names, " +
		"not numbers. These are `action` (authentication only), `authen_type`, `service`, `authen_method` " +
		"(authorization and accounting only) and `priv_lvl`. A value outside the protocol's list is written " +
		"`unknown_<n>`, where `<n>` is the header byte. A record for an unvalidated packet has no `packet_fields`; " +
		"it has the `unvalidated` block, which holds only cleartext header fields.\n")

	b.WriteString("\n## What the log never holds\n\n" +
		"The log never contains a token, a password, a challenge or a response. A credential appears only as " +
		"`credential_sha256`. The body of an unvalidated packet is never logged, only its hash. A token typed " +
		"as a username leaves `session.username` empty and sets `session.username_redacted` to `true`.\n")
	return b.String(), nil
}
