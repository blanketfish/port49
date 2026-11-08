package docgen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
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
	evidenceDir     = "docs/site/_snippets/evidence/"
	llmsPage        = "docs/site/llms.txt"
	tlsOutcomeKey   = "tls_outcome."
)

// specLabURL is the lab register in the spec on GitHub: a lab ID in a generated page links to it.
const specLabURL = "https://github.com/blanketfish/port49/blob/main/docs/design/2026-08-23-policy-engine-spec.md#15-lab-register"

// specIntro is the sentence that tells a reader what the copied spec text is.
const specIntro = "The meanings are the policy-engine spec's own text, so a section or decision number in one points into " +
	"[the spec](https://github.com/blanketfish/port49/blob/main/docs/design/2026-08-23-policy-engine-spec.md). " +
	"A lab ID in a meaning is an entry of the spec's lab register, marked open or closed. It stays open until a lab " +
	"test has measured the behavior it names, and a claim that cites an open entry is not yet measured."

var labIDRef = regexp.MustCompile(`\bL[0-9]+[a-z]?\b`)

// reasonPageLabBase is how the pages in docs/site/reference link the lab register page beside them.
const reasonPageLabBase = "lab-register.md"

// RenderLabIDs writes each lab ID in s as a link to its section of the lab register page with its status:
// "L4 (open)". base is the relative path from the generated page to that page (RegisterLinkFrom). An ID the
// register does not hold is an error. A code span that holds only the ID loses its backticks; an ID that is part
// of a path or a file name is left alone.
func RenderLabIDs(s string, reg map[string]LabRow, base string) (string, error) {
	var b strings.Builder
	last := 0
	for _, m := range labIDRef.FindAllStringIndex(s, -1) {
		start, end := m[0], m[1]
		if start > 0 && strings.ContainsRune("/-_.", rune(s[start-1])) {
			continue
		}
		if end < len(s) {
			next := s[end]
			if strings.ContainsRune("/-_", rune(next)) || (next == '.' && end+1 < len(s) && isAlnum(s[end+1])) {
				continue
			}
		}
		id := s[start:end]
		row, ok := reg[id]
		if !ok {
			return "", fmt.Errorf("lab ID %s is not in spec section 15", id)
		}
		status := "closed"
		if row.Open {
			status = "open"
		}
		if start > 0 && end < len(s) && s[start-1] == '`' && s[end] == '`' {
			start, end = start-1, end+1
		}
		b.WriteString(s[last:start])
		fmt.Fprintf(&b, "[%s (%s)](%s#%s)", id, status, base, strings.ToLower(id))
		last = end
	}
	b.WriteString(s[last:])
	return b.String(), nil
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

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
		if _, dup := meaning[c]; dup {
			return "", fmt.Errorf("reason codes: %s appears twice in the spec's table", c)
		}
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
		"The codes are in the order the server declares them.\n\n%s\n\n"+
		"| Reason | Meaning |\n|---|---|\n",
		jsonString("The closed list of reason codes a decision can carry, and what each means."), Header, specIntro)
	render := labRenderer(spec)
	for _, r := range decision.Reasons() {
		m, err := render(meaning[string(r)])
		if err != nil {
			return "", fmt.Errorf("reason %s: %w", r, err)
		}
		fmt.Fprintf(&b, "| `%s` | %s |\n", r, m)
	}
	return b.String(), nil
}

// labRenderer renders the lab IDs of a spec cell. It reads the register on first use, so a spec with no
// lab IDs needs none.
func labRenderer(spec []byte) func(string) (string, error) {
	var reg map[string]LabRow
	return func(s string) (string, error) {
		if !labIDRef.MatchString(s) {
			return s, nil
		}
		if reg == nil {
			var err error
			if reg, err = LabRegister(spec); err != nil {
				return "", err
			}
		}
		return RenderLabIDs(s, reg, reasonPageLabBase)
	}
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

// reportEvents are the events that share the envelope and decide nothing, from the spec's prose after the
// events table (section 5.7). Which events the code has is checked against these and the spec table.
var reportEvents = [][3]string{
	{"account", "daemon", "A device's accounting record: what the device did, after the fact. It carries the `record` block and no `policy` block."},
	{"account_gap", "daemon", "Accounting records port49 received and did not write to the log, with the `gap` block: the stage, how many and since when. A window with a gap cannot say a device did not ask."},
	{"unvalidated", "daemon", "A packet no key validated, or a connection the listener refused or ended: the `unvalidated` block, with a diagnosis, the cleartext header fields and a hash of the body. Never the body."},
	{"inventory_change", "daemon and broker", "One security-relevant change a policy or inventory swap made, in the `change` block, with the device in the `device` block. `port49_inventory_changes_total{kind}` counts them."},
	{"directory_forget", "broker", "An operator ran `port49 directory forget` for a principal, which deleted the principal's directory membership and the entry it was pinned to. The `forget` block holds the entry."},
	{"second_factor_reset", "broker", "An operator reset a person's second factor (`port49 directory reset-second-factor`), or `port49-broker init-enrollments` created the enrollment store. The `second_factor_reset` block holds the cleared enrollment."},
	{"sign_in_unlock", "broker", "An operator cleared a principal's failed-attempt count (`port49 directory unlock`). The `sign_in_unlock` block holds the count the broker held."},
	{"enrollments_import", "broker", "An operator ran `port49 directory import`, which filled or replaced the enrollment store. The `enrollments_import` block holds the record count and the export time."},
	{"generic_platform", "daemon", "port49d serves an admitted device whose platform has no adapter, with the set's generic adapter. One record per such device at start and at each bundle swap. It carries no verdict, and the broker does not write it."},
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
	fmt.Fprintf(&b, "---\ntitle: Decision log\ndescription: %s\n---\n\n%s\n\n# Decision log\n\n%s\n\n%s\n",
		jsonString(oneLine(desc[descDescription])), Header, strings.TrimSpace(desc[descIntro]), specIntro)

	render := labRenderer(spec)
	b.WriteString("\n## Events\n\nA decision event records one decision, with a verdict and a reason.\n\n" +
		"| Event | Emitted by | What it decides |\n|---|---|---|\n")
	for _, r := range events {
		cells := make([]string, 3)
		for i := range cells {
			var err error
			if cells[i], err = render(r[i]); err != nil {
				return "", fmt.Errorf("event %s: %w", r[0], err)
			}
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", cells[0], cells[1], cells[2])
	}
	b.WriteString("\n### Report events\n\nA report event shares the envelope but is not a decision: it carries no verdict.\n\n" +
		"| Event | Emitted by | What it reports |\n|---|---|---|\n")
	for _, r := range reportEvents {
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", r[0], r[1], r[2])
	}

	b.WriteString("\n## Fields\n\n| Field | Type | Description |\n|---|---|---|\n")
	for _, f := range fields {
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", f.Path, f.Type, cell(desc[f.Path]))
	}

	b.WriteString("\n## The tls_outcome values {#tls_outcome}\n\n" +
		"A record from the RFC 9887 (TACACS+ over TLS) listener carries `transport: \"tls\"`. An `unvalidated` " +
		"record with `diagnosis: tls_refused` carries the `tls_outcome` that says why the handshake was refused. " +
		"The handshake counter `port49_tls_handshakes_total` uses the same values as its `outcome` label. " +
		"Strike says whether the refusal counts against the source address, as a wrong key does.\n\n" +
		"| `tls_outcome` | Means | Strike |\n|---|---|---|\n")
	for _, o := range devicecert.Outcomes {
		strike := "no"
		if o.Struck() {
			strike = "yes"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", o, cell(desc[tlsOutcomeKey+string(o)]), strike)
	}
	b.WriteString("\nTwo more values are never in a record. They are label values of `port49_tls_handshakes_total` only, " +
		"and both mean the device was admitted:\n\n")
	for _, o := range []devicecert.Outcome{devicecert.OK, devicecert.Resumed} {
		fmt.Fprintf(&b, "- `%s`: %s\n", o, cell(desc[tlsOutcomeKey+string(o)]))
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
