package lab

import (
	"bytes"
	"errors"

	"gopkg.in/yaml.v3"
)

// The restart_etcd cell runs port49d on a real etcd, so the login contexts
// outlive the restart that the memory store loses them in. On etcd the broker
// is its own process (internal/config/stores.go: both stores memory, or both
// etcd with port49-broker beside port49d), so the conformance config, whose
// broker: block runs in the daemon, becomes two: the daemon's, here, and the
// broker's, splitBrokerYAML's.

// l80EtcdDaemonYAML is the conformance config's text (qualConfigYAML's) as the
// daemon of a split deployment runs it: no broker: block, the policy it admits
// from, the daemon's stores: block and its admin socket (etcd requires one).
// store is a stores: block that opens with a newline, as splitDaemonYAML takes it.
// It also returns the policy file the broker: block named, which the daemon and
// the broker's own config now both read.
func l80EtcdDaemonYAML(qual, admin, store string) (text, policy string, err error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(qual), &doc); err != nil {
		return "", "", err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return "", "", errors.New("the conformance config is not a mapping")
	}
	m := doc.Content[0]
	kept := m.Content[:0:0]
	cut := 0
	for i := 0; i+1 < len(m.Content); i += 2 {
		switch m.Content[i].Value {
		case "broker":
			cut++
			b := m.Content[i+1]
			for j := 0; b.Kind == yaml.MappingNode && j+1 < len(b.Content); j += 2 {
				if b.Content[j].Value == "policy_file" {
					policy = b.Content[j+1].Value
				}
			}
			continue
		case "policy", "stores", "admin_socket":
			return "", "", errors.New("the conformance config already has a " + m.Content[i].Value + ": key")
		}
		kept = append(kept, m.Content[i], m.Content[i+1])
	}
	if cut != 1 || policy == "" {
		return "", "", errors.New("the conformance config has no single broker: block with a policy_file to move out of the daemon")
	}
	m.Content = kept
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return "", "", err
	}
	if err := enc.Close(); err != nil {
		return "", "", err
	}
	return buf.String() + "\npolicy:\n  file: " + policy + "\n  watch_interval: 1s\n" + store + "admin_socket: " + admin + "\n", policy, nil
}
