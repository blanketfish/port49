package projection

import (
	"slices"
	"testing"

	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
)

// carvedInput is a readonly granted `show **` less the denies, on a tree that
// proves each word of the proven rules, with view-configuration's carve-outs
// and the entry deny: the fixture of TestACarvedPermitGoesOutAsItsCarveOuts.
func carvedInput(carves []string, proven []string, denies ...string) Input {
	rules := []engine.Rule{permit("show **")}
	for _, d := range denies {
		rules = append(rules, deny(d))
	}
	in := measuredInput(platform.BitDeliveryUserPermissions, "readonly", JunosFacts, rules...)
	in.Dialect.CarveOuts = map[string][]string{"view-configuration": carves}
	var reach []string
	for _, r := range in.Dialect.Bits {
		reach = append(reach, r...)
	}
	in.Keywords = keywordTree(append(reach, proven...)...)
	return entry(in)
}

// The guards inside carvedAllows each close the composition as the refused
// shape, not as a witness failure (review M1). `contains(p, c)` and
// `within(c)` are unreachable: a carve-out wider than p that meets p holds a
// deny beneath p too, so allowable(c) refuses first, and a permit within the
// ceiling meets no carve-out of a bit outside it.
func TestACarvedPermitIsRefusedWhereACarveOutCannotBeAllowed(t *testing.T) {
	// A deny beneath a carve-out the permit does not deny whole: an allow of
	// `show log` would beat the deny of `show log messages` (L11).
	in := carvedInput([]string{"show configuration **", "show log **"}, []string{"show log messages **"},
		"show configuration **", "show log messages **")
	res, err := Project(in)
	if err != nil || res.Shape != ShapeFailClosed || res.FailClosed != FailRefusedShape {
		t.Fatalf("deny beneath a carve-out: %s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
	if res.Device([]string{"show", "log", "messages"}) {
		t.Error("the device runs show log messages")
	}
	// A carve-out the tree does not prove cannot be allowed: an allow of it
	// never matches on the device.
	res, err = Project(carvedInput([]string{"show configuration **", "show zzz **"}, nil, "show configuration **"))
	if err != nil || res.Shape != ShapeFailClosed || res.FailClosed != FailRefusedShape {
		t.Fatalf("unsendable carve-out: %s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
	// The same, with the carve-outs the shipped tree proves, is the capability shape.
	res, err = Project(carvedInput([]string{"show configuration **", "show log **"}, []string{"show log **"},
		"show configuration **"))
	if err != nil || res.Shape != ShapeCapability {
		t.Fatalf("control: %s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
}

// The narrow shape wins over a capability shape with an allow beyond its bits
// only where it leaves off nothing the capability shape sends (review M2).
func TestTheNarrowPreferenceLeavesOffNothingMore(t *testing.T) {
	grant := []engine.Rule{permit("show **"), permit("ping **"), deny("clear bgp **")}
	in := func(extra ...engine.Rule) Input {
		return entry(measuredInput(platform.BitDeliveryUserPermissions, "operator", JunosFacts,
			append(slices.Clone(grant), extra...)...))
	}
	// Control: the capability shape's `ping **` is beyond its bits, and the
	// narrow shape's bits reach all of it.
	res, err := Project(in())
	if err != nil || res.Shape != ShapeNarrow || len(res.Unreached) != 0 {
		t.Fatalf("control: %s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
	// `show route table x` is no keyword path: the narrow shape would send an
	// allow of a permit the capability shape's bits already carry, and the
	// device would never match it, so the narrow shape would leave it off.
	res, err = Project(in(permit("show route table x")))
	if err != nil || res.Shape != ShapeCapability || len(res.Unreached) != 2 || len(res.Unsent) != 0 {
		t.Fatalf("unsent: %s %q unreached %v unsent %v %+v %v", res.Shape, res.Attributes, res.Unreached, res.Unsent,
			res.Refusal, err)
	}
}

// operatorXMLMode is an operator granted every baseline word, with the
// baseline's `xml-mode **` that no tree proves, and the entry deny.
func operatorXMLMode(f Facts, extra ...engine.Rule) Input {
	rules := append(slices.Concat(operatorGrant(), []engine.Rule{permit("start **")}), extra...)
	in := measuredInput(platform.BitDeliveryUserPermissions, "operator", f, rules...)
	in.Dialect.Bits[platform.BaselineBit] = append(in.Dialect.Bits[platform.BaselineBit], "xml-mode **")
	return entry(in)
}

// Where `xml-mode **` is the only baseline deny, it alone puts the entry deny
// on the wire; a reply that ignored it would send no deny and open xml-mode
// (review M3).
func TestTheClosedDenyAloneBringsTheEntryDeny(t *testing.T) {
	res, err := Project(operatorXMLMode(JunosFacts))
	if err != nil || res.Shape != ShapeCapability || len(res.Closed) != 1 || !entryDenied(res, "junoscript **") {
		t.Fatalf("%s %q closed %v %+v %v", res.Shape, res.Attributes, res.Closed, res.Refusal, err)
	}
	if res.Device([]string{"xml-mode", "netconf"}) || res.Device([]string{"junoscript"}) {
		t.Errorf("the device runs xml-mode: %q", res.Attributes)
	}
}

// Only a baseline deny is closed by the entry deny: an operator's own deny of
// `xml-mode` is a deny port49 cannot prove, and is not read as sent (review M3).
func TestOnlyABaselineDenyIsClosedByTheEntryDeny(t *testing.T) {
	res, err := Project(operatorXMLMode(JunosFacts, deny("xml-mode **")))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Closed {
		if c.Role != platform.BaselineBit {
			t.Errorf("closed a grant deny: %v (shape %s)", c, res.Shape)
		}
	}
	if res.Device([]string{"xml-mode", "netconf"}) {
		t.Errorf("the device runs xml-mode: %s %q", res.Shape, res.Attributes)
	}
}

// Where a wire deny binds RPCs, the baseline's `xml-mode **` is no deny the
// entry deny closes: it is sent or the composition goes narrow, never sent as
// nothing (review M3).
func TestNothingIsClosedWhereADenyBindsRPCs(t *testing.T) {
	f := JunosFacts
	f.DenyBindsRPCs = true
	res, err := Project(operatorXMLMode(f))
	// The composition does not fit (overflow) with the deny sent; if the deny
	// were wrongly dropped the witness, not the generator, would fail it.
	if err != nil || len(res.Closed) != 0 || res.Device([]string{"xml-mode", "netconf"}) ||
		res.FailClosed == FailUnsound {
		t.Fatalf("%s %q closed %v %+v %v", res.Shape, res.Attributes, res.Closed, res.Refusal, err)
	}
}

// withReach is in with its keyword tree rebuilt from the dialect's bits, as
// measuredInput builds it, plus the rules proven.
func withReach(in Input, proven ...string) Input {
	var reach []string
	for _, r := range in.Dialect.Bits {
		reach = append(reach, r...)
	}
	in.Keywords = keywordTree(append(reach, proven...)...)
	return in
}

// A permit the sent bits do not reach, whose deny beneath it keeps an allow
// from being sent, is refused, not dropped: `monitor **` is the trace bit's,
// and with view-configuration unusable only `view` is sent. The witness looks
// for the device running too much, so it would not see the permit vanish
// (re-review, reach(held)).
func TestACarvedPermitTheSentBitsDoNotReachIsRefused(t *testing.T) {
	rules := []engine.Rule{permit("show **"), permit("request flight-recorder **"), permit("request pppoe **"),
		permit("request snmp **"), permit("request validation **"), permit("test **"), permit("monitor **"),
		deny("monitor interface **")}
	in := measuredInput(platform.BitDeliveryUserPermissions, "readonly", JunosFacts, rules...)
	in.Dialect.Bits["view-configuration"] = append(in.Dialect.Bits["view-configuration"], "clear zzz **")
	res, err := Project(withReach(entry(in), "monitor interface **"))
	if err != nil || res.Shape != ShapeFailClosed || res.FailClosed != FailRefusedShape {
		t.Fatalf("%s %q allows %v unreached %v beyond %v unsent %v %+v %v", res.Shape, res.Attributes, res.Allows,
			res.Unreached, res.Beyond, res.Unsent, res.Refusal, err)
	}
}

// A bit whose reach names an argument can be wider than the permit by a
// carve-out the permit does not contain: `show * brief` reaches `show
// configuration brief`, so an allow of the carve-out `show configuration **`
// would run more than the permit, and the composition is refused rather than
// left to the witness (re-review, contains(p, c)).
func TestACarveOutWiderThanThePermitIsRefused(t *testing.T) {
	in := measuredInput(platform.BitDeliveryUserPermissions, "readonly", JunosFacts, permit("show * brief"),
		deny("show interfaces brief"))
	in.Dialect.CarveOuts = map[string][]string{"view-configuration": {"show configuration **", "show log **"}}
	in = withReach(in, "show interfaces brief", "show log **")
	in.Dialect.Bits["brief"] = []string{"show * brief"}
	in.Bits = append(slices.Clone(in.Bits), "brief")
	in.Dialect.CeilingBits["readonly"] = append(slices.Clone(in.Dialect.CeilingBits["readonly"]), "brief")
	res, err := Project(entry(in))
	if err != nil || res.Shape != ShapeFailClosed || res.FailClosed != FailRefusedShape {
		t.Fatalf("%s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
}

// A carve-out of a bit outside the ceiling, held by a deny, is no reason to
// give up the capability shape: the sent bits carry `show **`, and the narrow
// shape, which checks the ceiling alone, would put it beyond the level and
// drop the readonly's whole `show` grant (re-review, Beyond subset).
func TestTheNarrowPreferenceKeepsTheCapabilityShapeWhereItWouldDropAPermit(t *testing.T) {
	in := measuredInput(platform.BitDeliveryUserPermissions, "readonly", JunosFacts, permit("show **"),
		permit("monitor **"), deny("show configuration **"), deny("show log **"))
	in.Dialect.Bits["secret"] = []string{"show log **"}
	in.Dialect.Bits["view-configuration"] = append(in.Dialect.Bits["view-configuration"], "clear zzz **")
	in.Dialect.CarveOuts = map[string][]string{"view-configuration": {"show configuration **"}, "secret": {"show log **"}}
	res, err := Project(withReach(entry(in)))
	if err != nil || res.Shape != ShapeCapability || len(res.Beyond) != 0 || !res.Device([]string{"show", "version"}) {
		t.Fatalf("%s %q beyond %v unreached %v %+v %v", res.Shape, res.Attributes, res.Beyond, res.Unreached,
			res.Refusal, err)
	}
}
