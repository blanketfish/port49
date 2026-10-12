package projection

import (
	"slices"
	"strings"
	"testing"
)

// predictInput is a readonly granted `show **` less `show security **`, whose
// reply is `view` and an allow of each of view-configuration's carve-outs
// (TestACarvedPermitGoesOutAsItsCarveOuts), under the facts f.
func predictInput(f Facts) Input {
	carves := []string{"show configuration **", "show log **"}
	in := carvedInput(carves, append(slices.Clone(carves), "show security **"), "show security **")
	in.Facts = f
	return in
}

func shown(vs [][]string) string {
	var out []string
	for _, v := range vs {
		out = append(out, strings.Join(v, " "))
	}
	return strings.Join(out, "; ")
}

// Under `view` without view-configuration, a matching allow of `show
// configuration` was refused and the allows of `show log` ran, on both images
// (L26c-projected-juniper_*.md, the readonly rows): the prediction reads each
// so, and reports no allow it has a measurement for as unmeasured.
func TestThePredictionReadsAnAllowPastACarveOutAsMeasured(t *testing.T) {
	res, err := Project(predictInput(JunosFacts))
	if err != nil || res.Shape != ShapeCapability || len(res.Unreached) != 2 {
		t.Fatalf("%s %q unreached %v %+v %v", res.Shape, res.Attributes, res.Unreached, res.Refusal, err)
	}
	if res.Device([]string{"show", "configuration", "system"}) || !res.Device([]string{"show", "log", "messages"}) ||
		!res.Device([]string{"show", "version"}) {
		t.Errorf("prediction: %q", res.Attributes)
	}
	if res.Unmeasured([]string{"show", "configuration", "system"}) || res.Unmeasured([]string{"show", "log", "messages"}) ||
		len(res.UnmeasuredAllows()) != 0 {
		t.Errorf("unmeasured: %v", res.UnmeasuredAllows())
	}
	n := shown(res.Narrower(20))
	if !strings.Contains(n, "show configuration") || strings.Contains(n, "show log") {
		t.Errorf("narrower: %q", n)
	}
}

// A carve-out no cell measured keeps the wider reading: the device is
// predicted to run the allow, and the allow is reported unmeasured.
func TestACarveOutNoCellMeasuredStaysUnmeasured(t *testing.T) {
	f := JunosFacts
	f.AllowPastCarve = map[string]bool{"show configuration **": false}
	res, err := Project(predictInput(f))
	if err != nil || res.Shape != ShapeCapability || len(res.Unreached) != 2 {
		t.Fatalf("%s %q unreached %v %+v %v", res.Shape, res.Attributes, res.Unreached, res.Refusal, err)
	}
	if res.Device([]string{"show", "configuration", "system"}) || !res.Device([]string{"show", "log", "messages"}) {
		t.Errorf("prediction: %q", res.Attributes)
	}
	if res.Unmeasured([]string{"show", "configuration", "system"}) || !res.Unmeasured([]string{"show", "log", "messages"}) {
		t.Errorf("unmeasured: show configuration %v, show log %v",
			res.Unmeasured([]string{"show", "configuration", "system"}), res.Unmeasured([]string{"show", "log", "messages"}))
	}
	if u := res.UnmeasuredAllows(); len(u) != 1 || u[0].Rule != "show log **" {
		t.Errorf("unmeasured allows: %v", u)
	}
	if n := shown(res.Narrower(20)); !strings.Contains(n, "show log") || !strings.Contains(n, "show configuration") {
		t.Errorf("narrower: %q", n)
	}

	f.AllowPastCarve = nil
	res, err = Project(predictInput(f))
	if err != nil || !res.Device([]string{"show", "configuration", "system"}) ||
		!res.Unmeasured([]string{"show", "configuration", "system"}) || len(res.UnmeasuredAllows()) != 2 {
		t.Errorf("no measurement: %v %v", err, res.UnmeasuredAllows())
	}
}

// The reply is the same whatever the allows are measured to do: only the
// prediction narrows, never what is sent.
func TestTheMeasuredAllowsChangeNoReply(t *testing.T) {
	var was, now Result
	var err error
	f := JunosFacts
	f.AllowPastCarve = nil
	if was, err = Project(predictInput(f)); err != nil {
		t.Fatal(err)
	}
	if now, err = Project(predictInput(JunosFacts)); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(was.Attributes, now.Attributes) || was.Shape != now.Shape ||
		len(was.Unreached) != len(now.Unreached) {
		t.Errorf("the reply moved:\n%q\n%q", was.Attributes, now.Attributes)
	}
}
