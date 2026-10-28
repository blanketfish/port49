// Package sdtest is what the systemd smoke (plan 12b, Task 9) rewrites in the shipped files, and
// reads from systemd, as plain functions a unit test can hold without Docker. UNVERIFIED until the
// smoke runs: the shipped files are the input; nothing here has met a real systemd.
package sdtest

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

func itoa(n int) string { return strconv.Itoa(n) }

// ClientPort and PeerPort are etcd member n's ports in the one container (n is 1 to 3):
// 2379/2380, 2479/2480, 2579/2580.
func ClientPort(n int) int { return 2379 + 100*(n-1) }
func PeerPort(n int) int   { return 2380 + 100*(n-1) }

// Member is deploy/systemd/examples/etcd-<n>.yaml for three members in one container: every
// example.com name becomes localhost (the member certificates answer to it) at the member's own
// port, and the 0.0.0.0 listeners become 127.0.0.1.
func Member(body string, n int) (string, error) {
	out := body
	for m := 1; m <= 3; m++ {
		host := "https://etcd-" + itoa(m) + ".example.com"
		out = strings.ReplaceAll(out, host+":2379", "https://localhost:"+itoa(ClientPort(m)))
		out = strings.ReplaceAll(out, host+":2380", "https://localhost:"+itoa(PeerPort(m)))
	}
	out = strings.ReplaceAll(out, "https://0.0.0.0:2379", "https://127.0.0.1:"+itoa(ClientPort(n)))
	out = strings.ReplaceAll(out, "https://0.0.0.0:2380", "https://127.0.0.1:"+itoa(PeerPort(n)))
	if out == body {
		return "", errors.New("sdtest: the etcd member file names nothing to rewrite")
	}
	return out, nil
}

// Endpoints is a port49d or broker config with its three example.com member URLs made the
// container's.
func Endpoints(body string) (string, error) {
	out := body
	for m := 1; m <= 3; m++ {
		out = strings.ReplaceAll(out, "https://etcd-"+itoa(m)+".example.com:2379", "https://localhost:"+itoa(ClientPort(m)))
	}
	if out == body {
		return "", errors.New("sdtest: the config names no etcd endpoint to rewrite")
	}
	return out, nil
}

// Policy is the shipped starting policy for the smoke: the device set is named k (the shared
// RotateCell's name) and read from the one file v1 in the keys directory, and the group admits
// subnet.
func Policy(body, subnet string) (string, error) {
	out := body
	for _, r := range [][2]string{
		{"192.0.2.0/24", subnet},
		{"key_ref: example}", "key_ref: k}"},
		{"\n  example:\n", "\n  k:\n"},
		{"file:/etc/port49/keys/example-v1", "file:/etc/port49/keys/tacacs_v1"},
	} {
		if !strings.Contains(out, r[0]) {
			return "", fmt.Errorf("sdtest: the policy has no %q to rewrite", r[0])
		}
		out = strings.ReplaceAll(out, r[0], r[1])
	}
	return out, nil
}

// NoKeys is policy without its keys: block (the key groups still name a key set), which port49d
// refuses at every load.
func NoKeys(policy string) (string, error) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(policy), &doc); err != nil {
		return "", err
	}
	if _, ok := doc["keys"]; !ok {
		return "", errors.New("sdtest: the policy has no keys: block")
	}
	delete(doc, "keys")
	b, err := yaml.Marshal(doc)
	return string(b), err
}

// Broker is the shipped broker config for a trial PKI (no OCSP responder) with its metrics on
// every address, so the host reaches them through the published port.
func Broker(body string) (string, error) {
	out := strings.Replace(body, "certificate_status: {ocsp: {use_aia: true}}", "certificate_status: {disabled: true}", 1)
	out = strings.Replace(out, `metrics_listen: "127.0.0.1:9050"`, `metrics_listen: ":9050"`, 1)
	if !strings.Contains(out, "disabled: true") || !strings.Contains(out, `metrics_listen: ":9050"`) {
		return "", errors.New("sdtest: the broker config lacks the lines the smoke rewrites")
	}
	return out, nil
}

// Daemon is the shipped port49d config with its metrics on every address.
func Daemon(body string) (string, error) {
	out := strings.Replace(body, `metrics_listen: "127.0.0.1:9049"`, `metrics_listen: ":9049"`, 1)
	if out == body {
		return "", errors.New("sdtest: the port49d config has no metrics_listen to rewrite")
	}
	return out, nil
}

// ParseShow reads `systemctl show` output: KEY=VALUE lines.
func ParseShow(out string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			m[k] = v
		}
	}
	return m
}

// Refusal reports whether line is the fence's refusal naming dir: it names the directory and says
// it is writable by others.
func Refusal(line, dir string) bool {
	return strings.Contains(line, " "+dir+" is mode ") && strings.Contains(line, "writable by others")
}
