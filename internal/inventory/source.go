package inventory

import (
	"context"
	"fmt"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/fence"
)

// Source is one source of truth the service syncs from (spec §10,
// "Connectors and sync cadence"). Fetch returns every device the source
// holds, as facts: name, platform, addresses, attributes, transport. It
// never returns a key assignment (spec §13, decision 30). A source that
// cannot answer returns an error, and the sync keeps the bundle published.
// Fetch MUST return when ctx ends: the syncer gives each sync sync_timeout
// (default 5m), and a source that outlives it holds the schedule and a
// shutdown. Plan 6c's NetBox and Nautobot connectors implement it.
type Source interface {
	Name() string
	Fetch(ctx context.Context) (admission.Inventory, error)
}

// maxSourceFile bounds a file source's read as inventory_file's is bounded.
const maxSourceFile = 64 << 20

// FileSource is the file connector spec §10 requires regardless: an
// inventory file in port49d's schema, read behind the write fence, since
// whoever can write it decides scope membership and the addresses a mint
// hands out within one pull.
type FileSource struct{ SourceName, Path string }

func (f FileSource) Name() string { return f.SourceName }

// Fetch reads the file. A key group or a device's key_ref pin refuses it
// whole, naming the device: key assignment is reviewed policy (plan 6b owner
// decision 3), and a file that carries one was written for port49d's own
// inventory_file, whose reader assigns what it says.
func (f FileSource) Fetch(context.Context) (admission.Inventory, error) {
	raw, err := fence.Read(f.Path, maxSourceFile, "file source")
	if err != nil {
		return admission.Inventory{}, err
	}
	inv, err := admission.ParseFile(raw, f.Path)
	if err != nil {
		return admission.Inventory{}, err
	}
	if len(inv.KeyGroups) > 0 {
		return admission.Inventory{}, fmt.Errorf("%s carries key_groups; the inventory service never assigns keys: "+
			"move the block to the policy file (spec §13, decision 30)", f.Path)
	}
	for i, d := range inv.Devices {
		if d.KeyRef == "" {
			continue
		}
		if !bundle.NameOK(d.Name) {
			// A key group cannot match a position: the name is fixed first.
			return admission.Inventory{}, fmt.Errorf("%s: device %s pins key_ref; the inventory service never "+
				"assigns keys, and its name is not one a policy key group can match: fix its name at the source, "+
				"then move the pin to the policy file (spec §13, decision 30)", f.Path, deviceLabel(i, d.Name))
		}
		// The fix names the device: a pin is a policy key group matching
		// the name, tier 1 (Task 3a).
		return admission.Inventory{}, fmt.Errorf("%s: device %s pins key_ref; the inventory service never "+
			"assigns keys: pin it in the policy file with {match: {name: %s}, key_ref: ...}, which is tier 1, "+
			"and remove the pin here (spec §13, decision 30)", f.Path, d.Name, d.Name)
	}
	return inv, nil
}

// NewSources builds each configured source. Load has refused every type
// this build does not have.
func NewSources(cfgs []SourceConfig) ([]Source, error) {
	var out []Source
	for _, c := range cfgs {
		switch c.Type {
		case "file":
			out = append(out, FileSource{SourceName: c.Name, Path: c.Path})
		default:
			return nil, fmt.Errorf("port49-inventory: source %s: type %s is not built", c.Name, c.Type)
		}
	}
	return out, nil
}

// deviceLabel is a device as a line names it: its name where the name can
// reach a line as it is (bundle.NameOK), and otherwise its position.
func deviceLabel(i int, name string) string {
	if bundle.NameOK(name) {
		return name
	}
	return fmt.Sprintf("#%d", i)
}
