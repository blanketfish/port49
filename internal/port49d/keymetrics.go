package port49d

import (
	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/policy"
)

// singleDeviceKeyRefs is the key_refs held exactly once in keyRefs, which has
// one admitted device's key_ref per entry. The key series report those under
// one label (metrics.SingleDeviceKeyRef), so none names a device.
func singleDeviceKeyRefs(keyRefs []string) map[string]bool {
	n := map[string]int{}
	for _, r := range keyRefs {
		if r != "" {
			n[r]++
		}
	}
	out := map[string]bool{}
	for r, c := range n {
		if c == 1 {
			out[r] = true
		}
	}
	return out
}

// policySingleDeviceKeyRefs is singleDeviceKeyRefs over the devices pol admits.
func policySingleDeviceKeyRefs(pol *policy.Policy) map[string]bool {
	var refs []string
	for _, d := range pol.Devices() {
		if a, ok := pol.Admitted(d.Name); ok && a.Refused == "" {
			refs = append(refs, a.KeyRef)
		}
	}
	return singleDeviceKeyRefs(refs)
}

// indexSingleDeviceKeyRefs is singleDeviceKeyRefs over the admission index
// config.Load built, for a start with no policy.
func indexSingleDeviceKeyRefs(cfg config.Config) map[string]bool {
	var refs []string
	for _, d := range cfg.Inventory.Devices {
		if len(d.Addresses) == 0 || cfg.Admission == nil {
			continue
		}
		if r, ok := cfg.Admission.Lookup(d.Addresses[0]); ok && r.Refused == "" {
			refs = append(refs, r.KeyRef)
		}
	}
	return singleDeviceKeyRefs(refs)
}
