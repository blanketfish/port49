//go:build lab

package lab

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// sotAdmin is the harness's hands on a running stack (run.sh <stack> l33 or
// e2e): the writes a test makes so the connector has something to read,
// over the stack's own plain-HTTP port, as the recorder seeds it. It is
// never the connector's path. Its errors carry status codes and the
// product's error text, never the token.
type sotAdmin struct {
	stack, product, base, auth string
	c                          *http.Client
}

func newSoTAdmin(t *testing.T) *sotAdmin {
	t.Helper()
	stack := os.Getenv("L32_STACK")
	return &sotAdmin{stack: stack, product: strings.SplitN(stack, "-", 2)[0], base: os.Getenv("L33_DIRECT_URL"),
		auth: l32Auth(), c: &http.Client{Timeout: time.Minute}}
}

// nautobot2 is a stack that spells Nautobot 2.x's way (L27, L30): role,
// location, statuses by name.
func (a *sotAdmin) nautobot2() bool { return a.stack == "nautobot-2" || a.stack == "nautobot-3" }

// statusWord is s as the stack writes a status: "Active" on Nautobot 2.x
// and 3.x, "active" elsewhere (L27).
func (a *sotAdmin) statusWord(s string) string {
	if a.nautobot2() {
		return strings.ToUpper(s[:1]) + s[1:]
	}
	return s
}

func (a *sotAdmin) call(method, path string, body any) (int, map[string]any, error) {
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, a.base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", a.auth)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var m map[string]any
	json.Unmarshal(raw, &m)
	if resp.StatusCode >= 300 {
		return resp.StatusCode, m, fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, oneLine(string(raw)))
	}
	return resp.StatusCode, m, nil
}

// first is results[0] of a GET.
func (a *sotAdmin) first(path string) (map[string]any, error) {
	_, m, err := a.call(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	rs, _ := m["results"].([]any)
	if len(rs) == 0 {
		return nil, fmt.Errorf("GET %s: no results", path)
	}
	r, _ := rs[0].(map[string]any)
	return r, nil
}

func idOf(v any) any { m, _ := v.(map[string]any); return m["id"] }

// removeWebhooks deletes every event rule (NetBox) and webhook named name:
// the recorder's, which point at a listener that has gone.
func (a *sotAdmin) removeWebhooks(name string) error {
	paths := []string{"/api/extras/webhooks/"}
	if a.product == "netbox" {
		paths = []string{"/api/extras/event-rules/", "/api/extras/webhooks/"}
	}
	for _, p := range paths {
		_, m, err := a.call(http.MethodGet, p+"?name="+url.QueryEscape(name), nil)
		if err != nil {
			return err
		}
		rs, _ := m["results"].([]any)
		for _, r := range rs {
			if _, _, err := a.call(http.MethodDelete, fmt.Sprintf("%s%v/", p, idOf(r)), nil); err != nil {
				return err
			}
		}
	}
	return nil
}

// webhook creates a webhook for device create, update and delete, to
// payload, signed with secret, verified against the CA at caPath inside the
// worker; NetBox also needs an event rule, in its release's spelling (L27).
// It returns each call's status, for the note.
func (a *sotAdmin) webhook(name, payload, secret, caPath string) ([]string, error) {
	hook := map[string]any{"name": name, "payload_url": payload, "http_method": "POST",
		"http_content_type": "application/json", "secret": secret, "ssl_verification": true, "ca_file_path": caPath,
		"enabled": true}
	if a.product == "nautobot" {
		hook["content_types"] = []any{"dcim.device"}
		hook["type_create"], hook["type_update"], hook["type_delete"] = true, true, true
	}
	status, m, err := a.call(http.MethodPost, "/api/extras/webhooks/", hook)
	calls := []string{fmt.Sprintf("webhook %d", status)}
	if err != nil || a.product == "nautobot" {
		return calls, err
	}
	rule := map[string]any{"name": name, "action_type": "webhook", "action_object_type": "extras.webhook",
		"action_object_id": m["id"], "enabled": true}
	if a.stack == "netbox-3.7" {
		rule["content_types"] = []any{"dcim.device"}
		rule["type_create"], rule["type_update"], rule["type_delete"] = true, true, true
	} else {
		rule["object_types"] = []any{"dcim.device"}
		rule["event_types"] = []any{"object_created", "object_updated", "object_deleted"}
	}
	status, _, err = a.call(http.MethodPost, "/api/extras/event-rules/", rule)
	return append(calls, fmt.Sprintf("event_rule %d", status)), err
}

// createDevice creates name as leaf-01 is: its type, role, site or location
// and platform, status active.
func (a *sotAdmin) createDevice(name string) (any, error) {
	leaf, err := a.first("/api/dcim/devices/?name=leaf-01")
	if err != nil {
		return nil, err
	}
	body := map[string]any{"name": name, "device_type": idOf(leaf["device_type"]), "platform": idOf(leaf["platform"]),
		"status": a.statusWord("active")}
	switch {
	case a.product == "netbox":
		body["role"], body["site"] = idOf(leaf["role"]), idOf(leaf["site"])
	case a.stack == "nautobot-1.6":
		body["device_role"], body["site"] = idOf(leaf["device_role"]), idOf(leaf["site"])
	default:
		body["role"], body["location"] = idOf(leaf["role"]), idOf(leaf["location"])
	}
	_, m, err := a.call(http.MethodPost, "/api/dcim/devices/", body)
	if err != nil {
		return nil, err
	}
	return m["id"], nil
}

func (a *sotAdmin) patchDevice(id any, body map[string]any) error {
	_, _, err := a.call(http.MethodPatch, fmt.Sprintf("/api/dcim/devices/%v/", id), body)
	return err
}

func (a *sotAdmin) deleteDevice(id any) error {
	_, _, err := a.call(http.MethodDelete, fmt.Sprintf("/api/dcim/devices/%v/", id), nil)
	return err
}

// addPrimary gives device id an interface Management1 holding addr, and
// makes addr its primary IPv4, as the recorder's seed does per release
// (tests/lab/cmd/sot-record/seed.go): Nautobot 2.x and 3.x need the address's
// parent prefix and bind it through ip-address-to-interface.
func (a *sotAdmin) addPrimary(id any, addr string) error {
	itf := map[string]any{"device": id, "name": "Management1", "type": "virtual"}
	if a.product == "nautobot" {
		itf["status"] = a.statusWord("active")
	}
	_, m, err := a.call(http.MethodPost, "/api/dcim/interfaces/", itf)
	if err != nil {
		return err
	}
	ifID := m["id"]
	var ipID any
	if a.nautobot2() {
		prefix := strings.Join(strings.Split(strings.TrimSuffix(addr, "/32"), ".")[:3], ".") + ".0/24"
		a.call(http.MethodPost, "/api/ipam/prefixes/", map[string]any{"prefix": prefix, "status": "Active"})
		p, err := a.first("/api/ipam/prefixes/?prefix=" + url.QueryEscape(prefix))
		if err != nil {
			return err
		}
		_, ip, err := a.call(http.MethodPost, "/api/ipam/ip-addresses/", map[string]any{"address": addr,
			"status": "Active", "parent": p["id"]})
		if err != nil {
			return err
		}
		ipID = ip["id"]
		if _, _, err := a.call(http.MethodPost, "/api/ipam/ip-address-to-interface/",
			map[string]any{"ip_address": ipID, "interface": ifID}); err != nil {
			return err
		}
	} else {
		ip := map[string]any{"address": addr, "assigned_object_type": "dcim.interface", "assigned_object_id": ifID}
		if a.product == "nautobot" {
			ip["status"] = "active"
		}
		_, m, err := a.call(http.MethodPost, "/api/ipam/ip-addresses/", ip)
		if err != nil {
			return err
		}
		ipID = m["id"]
	}
	return a.patchDevice(id, map[string]any{"primary_ip4": ipID})
}
