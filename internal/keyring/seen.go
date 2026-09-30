package keyring

import "sync"

// Seen remembers, per device, the key_ref and version its latest validated
// connection used since port49d started: what port49_key_version_devices
// counts. Only admitted devices are marked, so it is bounded by the inventory.
type Seen struct {
	mu   sync.Mutex
	last map[string]seenAs
}

type seenAs struct {
	ref     string
	version int
}

// Mark records that device's latest validated connection used ref's version.
func (s *Seen) Mark(device, ref string, version int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last == nil {
		s.last = map[string]seenAs{}
	}
	s.last[device] = seenAs{ref, version}
}

// Count is how many devices' latest validated connection used ref's version.
func (s *Seen) Count(ref string, version int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, a := range s.last {
		if a.ref == ref && a.version == version {
			n++
		}
	}
	return n
}
