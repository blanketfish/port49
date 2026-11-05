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

// policyKeyRefs is the key_ref of each device pol admits, one per device.
func policyKeyRefs(pol *policy.Policy) []string {
	var refs []string
	for _, d := range pol.Devices() {
		if a, ok := pol.Admitted(d.Name); ok && a.Refused == "" {
			refs = append(refs, a.KeyRef)
		}
	}
	return refs
}

// policySingleDeviceKeyRefs is singleDeviceKeyRefs over the devices pol admits.
func policySingleDeviceKeyRefs(pol *policy.Policy) map[string]bool {
	return singleDeviceKeyRefs(policyKeyRefs(pol))
}

// swapSingleDeviceKeyRefs is the set a swap from old to pol puts in force:
// pol's single-device key_refs, and every key_ref old held that pol gives
// fewer than two devices (none included). A packet admitted under old and
// counted after the set is stored may still carry such a key_ref, and
// naming it would name the one device that held it. Too wide only aggregates;
// too narrow leaks. old is nil at a start.
func swapSingleDeviceKeyRefs(old, pol *policy.Policy) map[string]bool {
	out := policySingleDeviceKeyRefs(pol)
	if old == nil {
		return out
	}
	held := map[string]int{}
	for _, r := range policyKeyRefs(pol) {
		held[r]++
	}
	for _, r := range policyKeyRefs(old) {
		if r != "" && held[r] < 2 {
			out[r] = true
		}
	}
	return out
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
