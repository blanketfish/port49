package platform

import (
	"reflect"
	"strings"
	"testing"
)

// junosProjected is a projected Junos adapter as a test writes one: spec §8's
// example bits, readonly and admin ceilings, one template per level.
func junosProjected(delivery string) Dialect {
	base, _ := Generic(UnpinnedSet)
	d := Spec{
		Supports:            &[]string{"session"},
		CommandProjection:   ptr(ProjectionJunosRegex),
		BitDelivery:         ptr(delivery),
		PrivilegeAttributes: ptr(ProjectionAttributes(ProjectionJunosRegex)),
		Bits: &map[string][]string{"view": {"show **"}, "view-configuration": {"show configuration **"},
			"clear": {"clear **"}, "all": {"**"}, BaselineBit: {"quit **", "set cli **"}},
		CarveOuts: &map[string][]string{"view-configuration": {"show configuration **"}},
		Privilege: &map[string][]string{"readonly": {"view", "view-configuration"}, "admin": {"all"}},
	}.Over(base)
	if delivery == BitDeliveryLocalUserName {
		d.LocalUserNames = map[string]string{"readonly": "p49-readonly", "admin": "p49-admin"}
	}
	return d
}

// On a projected platform `privilege` is each level's ceiling in bits: Over
// routes it to CeilingBits, renders no attribute for a level, and SpecOf
// writes it back under `privilege`, so export and the diff read it there.
func TestProjectedPrivilegeIsBits(t *testing.T) {
	d := junosProjected(BitDeliveryUserPermissions)
	if d.Levels != nil || !reflect.DeepEqual(d.CeilingBits["readonly"], []string{"view", "view-configuration"}) {
		t.Fatalf("levels %v, ceiling bits %v", d.Levels, d.CeilingBits)
	}
	if attrs, ok := d.Render("admin"); !ok || attrs != nil {
		t.Errorf("a projected level renders no attribute of its own: %v %v", attrs, ok)
	}
	if err := Validate("juniper_junos", d); err != nil {
		t.Fatal(err)
	}
	if got := SpecOf(d).Over(Dialect{}); !reflect.DeepEqual(got, d) {
		t.Errorf("round trip:\n got %+v\nwant %+v", got, d)
	}
	block := Spec{Privilege: &map[string][]string{"operator": {"view", "clear"}}}.Over(d)
	if !reflect.DeepEqual(block.CeilingBits["operator"], []string{"view", "clear"}) || block.Levels != nil {
		t.Errorf("a block over a projected platform sets bits: %v %v", block.CeilingBits, block.Levels)
	}
	if got := d.ExpandBits([]string{"all"}); !reflect.DeepEqual(got, []string{"all", "clear", "view", "view-configuration"}) {
		t.Errorf("all is every bit: %v", got)
	}
}

func TestValidateRefusesABadProjection(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(*Dialect)
		want string
	}{
		{"unknown projection", func(d *Dialect) { d.CommandProjection = "junos" }, "command_projection"},
		{"per command too", func(d *Dialect) { d.Supports = []string{"session", "commands"} }, "supports"},
		{"no bits", func(d *Dialect) { d.Bits = nil }, "bits is required"},
		{"a bit with a class", func(d *Dialect) { d.Bits["view"] = []string{"show interfaces @management"} },
			"bits.view[0]: term 3"},
		{"a ceiling naming no bit", func(d *Dialect) { d.CeilingBits["readonly"] = []string{"view", "vew"} },
			"privilege.readonly[1]: vew"},
		{"no delivery", func(d *Dialect) { d.BitDelivery = "" }, "bit_delivery"},
		{"a projection name not bearing privilege", func(d *Dialect) {
			d.PrivilegeAttributes = []string{"local-user-name"}
		}, "user-permissions is missing"},
		{"accepted attributes", func(d *Dialect) { d.AcceptedAttributes = []string{"local-user-name"} },
			"accepted_attributes"},
		{"templates under user_permissions", func(d *Dialect) { d.LocalUserNames = map[string]string{"admin": "a"} },
			"read only under bit_delivery"},
		{"a carve-out of an undeclared bit", func(d *Dialect) { d.CarveOuts["trace"] = []string{"monitor **"} },
			"carve_outs.trace"},
		{"a carve-out the bit does not reach", func(d *Dialect) {
			d.CarveOuts["view-configuration"] = []string{"show log **"}
		}, "carve_outs.view-configuration[0]: the bit's own reach does not hold it"},
		{"a carve-out of the baseline", func(d *Dialect) { d.CarveOuts[BaselineBit] = []string{"quit **"} },
			"never to baseline"},
		{"a level naming the baseline", func(d *Dialect) { d.CeilingBits["readonly"] = []string{"view", BaselineBit} },
			"baseline is held by every session"},
	} {
		d := with(junosProjected(BitDeliveryUserPermissions), c.edit)
		if err := Validate("juniper_junos", d); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	for _, c := range []struct {
		name string
		edit func(*Dialect)
		want string
	}{
		{"a level with no template", func(d *Dialect) { delete(d.LocalUserNames, "admin") }, "admin has no template"},
		{"a template that is no login name", func(d *Dialect) { d.LocalUserNames["admin"] = "P49 Admin" },
			"local_user_names.admin is not a login name"},
		{"two levels, one template, two classes", func(d *Dialect) { d.LocalUserNames["admin"] = "p49-readonly" },
			"share template p49-readonly"},
		{"a template for a level with no bits", func(d *Dialect) { d.LocalUserNames["operator"] = "p49-operator" },
			"operator has no bits"},
	} {
		d := with(junosProjected(BitDeliveryLocalUserName), c.edit)
		if err := Validate("juniper_junos", d); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	if err := Validate("juniper_junos", junosProjected(BitDeliveryLocalUserName)); err != nil {
		t.Errorf("local_user_name: %v", err)
	}
	// A projection key nothing reads reads as enforced.
	eos, _ := DialectFor("arista_eos")
	eos.BitDelivery = BitDeliveryLocalUserName
	if err := Validate("arista_eos", eos); err == nil || !strings.Contains(err.Error(), "read only with command_projection") {
		t.Errorf("bit_delivery with no projection: %v", err)
	}
}

func TestMonotoneBits(t *testing.T) {
	order := []string{"readonly", "operator", "admin"}
	d := junosProjected(BitDeliveryUserPermissions)
	if err := MonotoneBits("juniper_junos", d, order); err != nil {
		t.Fatalf("admin's all holds every bit: %v", err)
	}
	d.CeilingBits["operator"] = []string{"view", "clear"}
	if err := MonotoneBits("juniper_junos", d, order); err == nil || !strings.Contains(err.Error(),
		"privilege.readonly: view-configuration is not in operator's bits") {
		t.Errorf("readonly above operator: %v", err)
	}
}

// A projected platform owns every name Junos reads as a class's template,
// bits or regexes, numbered and in any case, and every name its adapter lists
// as bearing privilege; a platform that projects nothing owns none.
func TestProjectionOwns(t *testing.T) {
	d := junosProjected(BitDeliveryUserPermissions)
	for _, n := range []string{"allow-commands", "allow-commands2", "Deny-Commands1", "deny-configuration-regexps",
		"user-permissions2", "LOCAL-USER-NAME", "allow-configuration"} {
		if !d.ProjectionOwns(n) {
			t.Errorf("%s is not owned", n)
		}
	}
	for _, n := range []string{"home-directory", "allow-commandsx", "idletime"} {
		if d.ProjectionOwns(n) {
			t.Errorf("%s is owned", n)
		}
	}
	eos, _ := DialectFor("arista_eos")
	if eos.ProjectionOwns("allow-commands") {
		t.Error("a platform that projects nothing owns nothing")
	}
}
