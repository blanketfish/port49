package main

import (
	"encoding/json"
	"fmt"
)

type step struct {
	step, method, path string
	body               map[string]any
}

// seedFor is one device, leaf-01, with a management interface and a loopback,
// an address on each, the management one primary, a platform, a role, a site
// or location, a custom field os_version and a tag: every fact spec §10's
// connector maps. Each object is created by name and later calls name it by
// the id the product returned ("@step.id"). The calls are the newest major
// version's; a step suffixed _v1 or _v3 is the older version's spelling of
// the step before it, so both outcomes are recorded.
func seedFor(product string, r *recorder) []step {
	if product == "nautobot" {
		return []step{
			{"location_type", "POST", "/api/dcim/location-types/", map[string]any{"name": "Site", "content_types": []any{"dcim.device"}}},
			{"location", "POST", "/api/dcim/locations/", map[string]any{"name": "dc1", "location_type": "@location_type.id", "status": "Active"}},
			{"site_v1", "POST", "/api/dcim/sites/", map[string]any{"name": "dc1", "slug": "dc1", "status": "active"}},
			{"manufacturer", "POST", "/api/dcim/manufacturers/", map[string]any{"name": "Arista", "slug": "arista"}},
			{"device_type", "POST", "/api/dcim/device-types/", map[string]any{"manufacturer": "@manufacturer.id", "model": "vEOS", "slug": "veos"}},
			{"role", "POST", "/api/extras/roles/", map[string]any{"name": "leaf", "content_types": []any{"dcim.device"}}},
			{"role_v1", "POST", "/api/dcim/device-roles/", map[string]any{"name": "leaf", "slug": "leaf"}},
			{"platform", "POST", "/api/dcim/platforms/", map[string]any{"name": "eos", "slug": "eos", "network_driver": "arista_eos"}},
			{"tag", "POST", "/api/extras/tags/", map[string]any{"name": "port49", "slug": "port49", "content_types": []any{"dcim.device"}}},
			{"custom_field", "POST", "/api/extras/custom-fields/", map[string]any{"label": "os_version", "key": "os_version", "name": "os_version", "type": "text", "content_types": []any{"dcim.device"}}},
			{"device", "POST", "/api/dcim/devices/", map[string]any{"name": "leaf-01", "device_type": "@device_type.id", "role": "@role.id", "location": "@location.id", "platform": "@platform.id", "status": "Active", "custom_fields": map[string]any{"os_version": "4.31.2F"}, "tags": []any{"@tag.id"}}},
			{"device_v1", "POST", "/api/dcim/devices/", map[string]any{"name": "leaf-01", "device_type": "@device_type.id", "device_role": "@role_v1.id", "site": "@site_v1.id", "platform": "@platform.id", "status": "active", "custom_fields": map[string]any{"os_version": "4.31.2F"}, "tags": []any{"@tag.id"}}},
			{"mgmt", "POST", "/api/dcim/interfaces/", map[string]any{"device": "@device.id", "name": "Management1", "type": "virtual", "status": "Active"}},
			{"mgmt_v1", "POST", "/api/dcim/interfaces/", map[string]any{"device": "@device.id", "name": "Management1", "type": "virtual", "status": "active"}},
			{"loopback", "POST", "/api/dcim/interfaces/", map[string]any{"device": "@device.id", "name": "Loopback0", "type": "virtual", "status": "Active"}},
			{"loopback_v1", "POST", "/api/dcim/interfaces/", map[string]any{"device": "@device.id", "name": "Loopback0", "type": "virtual", "status": "active"}},
			{"prefix", "POST", "/api/ipam/prefixes/", map[string]any{"prefix": "10.0.0.0/8", "status": "Active"}},
			{"mgmt_ip", "POST", "/api/ipam/ip-addresses/", map[string]any{"address": "10.0.1.5/32", "status": "Active"}},
			{"mgmt_ip_v1", "POST", "/api/ipam/ip-addresses/", map[string]any{"address": "10.0.1.5/32", "status": "active", "assigned_object_type": "dcim.interface", "assigned_object_id": "@mgmt.id"}},
			{"loop_ip", "POST", "/api/ipam/ip-addresses/", map[string]any{"address": "10.0.1.6/32", "status": "Active"}},
			{"loop_ip_v1", "POST", "/api/ipam/ip-addresses/", map[string]any{"address": "10.0.1.6/32", "status": "active", "assigned_object_type": "dcim.interface", "assigned_object_id": "@loopback.id"}},
			// Nautobot 2.x refuses mgmt_ip and loop_ip: "One of parent or namespace must be provided".
			{"mgmt_ip_parent", "POST", "/api/ipam/ip-addresses/", map[string]any{"address": "10.0.1.5/32", "status": "Active", "parent": "@prefix.id"}},
			{"loop_ip_parent", "POST", "/api/ipam/ip-addresses/", map[string]any{"address": "10.0.1.6/32", "status": "Active", "parent": "@prefix.id"}},
			{"mgmt_bind", "POST", "/api/ipam/ip-address-to-interface/", map[string]any{"ip_address": "@mgmt_ip.id", "interface": "@mgmt.id"}},
			{"loop_bind", "POST", "/api/ipam/ip-address-to-interface/", map[string]any{"ip_address": "@loop_ip.id", "interface": "@loopback.id"}},
			// A Nautobot detail URL takes the object's UUID, never its name.
			{"primary", "PATCH", "/api/dcim/devices/@device.id/", map[string]any{"primary_ip4": "@mgmt_ip.id"}},
		}
	}
	return []step{
		{"site", "POST", "/api/dcim/sites/", map[string]any{"name": "dc1", "slug": "dc1"}},
		{"manufacturer", "POST", "/api/dcim/manufacturers/", map[string]any{"name": "Arista", "slug": "arista"}},
		{"device_type", "POST", "/api/dcim/device-types/", map[string]any{"manufacturer": "@manufacturer.id", "model": "vEOS", "slug": "veos"}},
		{"role", "POST", "/api/dcim/device-roles/", map[string]any{"name": "leaf", "slug": "leaf", "color": "00ff00"}},
		{"platform", "POST", "/api/dcim/platforms/", map[string]any{"name": "eos", "slug": "eos"}},
		{"tag", "POST", "/api/extras/tags/", map[string]any{"name": "port49", "slug": "port49"}},
		{"custom_field", "POST", "/api/extras/custom-fields/", map[string]any{"name": "os_version", "type": "text", "object_types": []any{"dcim.device"}}},
		{"custom_field_v3", "POST", "/api/extras/custom-fields/", map[string]any{"name": "os_version", "type": "text", "content_types": []any{"dcim.device"}}},
		{"device", "POST", "/api/dcim/devices/", map[string]any{"name": "leaf-01", "device_type": "@device_type.id", "role": "@role.id", "site": "@site.id", "platform": "@platform.id", "status": "active", "custom_fields": map[string]any{"os_version": "4.31.2F"}, "tags": []any{map[string]any{"slug": "port49"}}}},
		{"device_v3", "POST", "/api/dcim/devices/", map[string]any{"name": "leaf-01", "device_type": "@device_type.id", "device_role": "@role.id", "site": "@site.id", "platform": "@platform.id", "status": "active", "custom_fields": map[string]any{"os_version": "4.31.2F"}, "tags": []any{map[string]any{"slug": "port49"}}}},
		{"mgmt", "POST", "/api/dcim/interfaces/", map[string]any{"device": "@device.id", "name": "Management1", "type": "virtual"}},
		{"loopback", "POST", "/api/dcim/interfaces/", map[string]any{"device": "@device.id", "name": "Loopback0", "type": "virtual"}},
		{"mgmt_ip", "POST", "/api/ipam/ip-addresses/", map[string]any{"address": "10.0.1.5/32", "assigned_object_type": "dcim.interface", "assigned_object_id": "@mgmt.id"}},
		{"loop_ip", "POST", "/api/ipam/ip-addresses/", map[string]any{"address": "10.0.1.6/32", "assigned_object_type": "dcim.interface", "assigned_object_id": "@loopback.id"}},
		{"primary", "PATCH", "/api/dcim/devices/@device.id/", map[string]any{"primary_ip4": "@mgmt_ip.id"}},
	}
}

// graphQLCandidates are the query shapes to try, one device with every fact
// and every interface's addresses. The run records which each version takes.
func graphQLCandidates(product string) []string {
	if product == "nautobot" {
		return []string{
			`{ devices(name: "leaf-01") { name platform { name network_driver } location { name } role { name } primary_ip4 { address } _custom_field_data tags { name } interfaces { name ip_addresses { address } } } }`,
			`{ devices(name: "leaf-01") { name platform { slug } site { slug } device_role { slug } primary_ip4 { address } custom_fields tags { slug } interfaces { name ip_addresses { address } } } }`,
			// Nautobot 1.6 refused the two above on role and on custom_fields alone.
			`{ devices(name: "leaf-01") { name platform { slug network_driver } site { slug } device_role { slug } primary_ip4 { address } _custom_field_data tags { slug } interfaces { name ip_addresses { address } } } }`,
		}
	}
	return []string{
		`{ device_list(filters: {name: {exact: "leaf-01"}}) { name platform { slug } site { slug } role { slug } primary_ip4 { address } custom_fields tags { slug } interfaces { name ip_addresses { address } } } }`,
		`{ device_list(filters: {name: "leaf-01"}) { name platform { slug } site { slug } role { slug } primary_ip4 { address } custom_fields tags { slug } interfaces { name ip_addresses { address } } } }`,
		`{ device_list(name: "leaf-01") { name platform { slug } site { slug } device_role { slug } primary_ip4 { address } custom_fields tags { slug } interfaces { name ip_addresses { address } } } }`,
		// NetBox 3.7 refused the one above on device_role alone.
		`{ device_list(name: "leaf-01") { name platform { slug } site { slug } role { slug } primary_ip4 { address } custom_fields tags { slug } interfaces { name ip_addresses { address } } } }`,
	}
}

// webhookSteps configure a webhook to url with secret for device create,
// update and delete, then make one of each: an update of leaf-01's
// os_version, and a device leaf-02 created and deleted. The create has an
// older version's spelling after it, as the seed's steps do.
func webhookSteps(product, url, secret string) []step {
	hook := map[string]any{"name": "l27", "payload_url": url, "http_method": "POST", "http_content_type": "application/json", "secret": secret, "enabled": true}
	var setup []step
	switch product {
	case "nautobot":
		h := map[string]any{"content_types": []any{"dcim.device"}, "type_create": true, "type_update": true, "type_delete": true}
		for k, v := range hook {
			h[k] = v
		}
		setup = []step{{"webhook", "POST", "/api/extras/webhooks/", h}}
	default:
		v3 := map[string]any{"content_types": []any{"dcim.device"}, "type_create": true, "type_update": true, "type_delete": true}
		for k, v := range hook {
			v3[k] = v
		}
		setup = []step{
			{"webhook", "POST", "/api/extras/webhooks/", hook},
			{"event_rule", "POST", "/api/extras/event-rules/", map[string]any{"name": "l27", "object_types": []any{"dcim.device"}, "event_types": []any{"object_created", "object_updated", "object_deleted"}, "action_type": "webhook", "action_object_type": "extras.webhook", "action_object_id": "@webhook.id", "enabled": true}},
			{"webhook_v3", "POST", "/api/extras/webhooks/", v3},
			// NetBox 3.7 has event rules but refuses the one above: "content_types: This field is required".
			{"event_rule_v3", "POST", "/api/extras/event-rules/", map[string]any{"name": "l27", "content_types": []any{"dcim.device"}, "type_create": true, "type_update": true, "type_delete": true, "action_type": "webhook", "action_object_type": "extras.webhook", "action_object_id": "@webhook.id", "enabled": true}},
		}
	}
	second := map[string]any{"name": "leaf-02", "device_type": "@device_type.id", "role": "@role.id", "site": "@site.id", "status": "active"}
	secondLegacy := step{"create_2_v3", "POST", "/api/dcim/devices/", map[string]any{"name": "leaf-02", "device_type": "@device_type.id", "device_role": "@role.id", "site": "@site.id", "status": "active"}}
	if product == "nautobot" {
		second = map[string]any{"name": "leaf-02", "device_type": "@device_type.id", "role": "@role.id", "location": "@location.id", "status": "Active"}
		secondLegacy = step{"create_2_v1", "POST", "/api/dcim/devices/", map[string]any{"name": "leaf-02", "device_type": "@device_type.id", "device_role": "@role_v1.id", "site": "@site_v1.id", "status": "active"}}
	}
	return append(setup,
		step{"update", "PATCH", "/api/dcim/devices/@device.id/", map[string]any{"custom_fields": map[string]any{"os_version": "4.32.2F"}}},
		step{"create_2", "POST", "/api/dcim/devices/", second},
		secondLegacy,
		step{"delete_2", "DELETE", "/api/dcim/devices/@create_2.id/", nil},
	)
}

// seedMany creates devices leaf-002 .. leaf-<n> beside leaf-01, in one bulk
// POST per hundred (both products take a JSON list on the device endpoint),
// each naming the objects leaf-01's seed created. Only each call's status and
// how many it created are recorded: the bodies are leaf-01's shape n times.
func (r *recorder) seedMany(product string, n int) []map[string]any {
	var out []map[string]any
	for start := 2; start <= n; start += 100 {
		var batch []any
		for i := start; i < start+100 && i <= n; i++ {
			d := map[string]any{"name": fmt.Sprintf("leaf-%03d", i), "device_type": "@device_type.id",
				"platform": "@platform.id", "status": "active"}
			if product == "nautobot" {
				d["status"] = "Active"
				d["role"], d["location"] = "@role.id", "@location.id"
				if r.legacy {
					d["status"], d["device_role"], d["site"] = "active", "@role_v1.id", "@site_v1.id"
					delete(d, "role")
					delete(d, "location")
				}
			} else {
				d["role"], d["site"] = "@role.id", "@site.id"
			}
			batch = append(batch, d)
		}
		x := r.call(fmt.Sprintf("bulk_%d", start), "POST", "/api/dcim/devices/", batch)
		var created []any
		_ = json.Unmarshal(x.Body, &created)
		out = append(out, map[string]any{"step": x.Step, "status": x.Status, "sent": len(batch), "created": len(created)})
		fmt.Printf("sot-record: bulk %d: %d, %d created\n", start, x.Status, len(created))
	}
	return out
}

// pages reads the device list limit at a time and follows each `next` as the
// product wrote it, to a null or 100 pages, recording per page the status,
// count, next and previous, and in all every name seen and every name seen
// twice. next is followed verbatim — host, scheme and all — since whether it
// can be is the question.
func (r *recorder) pages(limit int) map[string]any {
	next := fmt.Sprintf("%s/api/dcim/devices/?limit=%d", r.base, limit)
	var pages []map[string]any
	seen := map[string]bool{}
	var names, repeated []string
	count, ended := 0, "page_cap"
	for i := 0; i < 100 && next != ""; i++ {
		x := r.callURL(fmt.Sprintf("page_%d", i), next)
		var body struct {
			Count    int     `json:"count"`
			Next     *string `json:"next"`
			Previous *string `json:"previous"`
			Results  []struct {
				Name string `json:"name"`
			} `json:"results"`
		}
		_ = json.Unmarshal(x.Body, &body)
		pages = append(pages, map[string]any{"step": x.Step, "url": next, "status": x.Status, "count": body.Count,
			"next": body.Next, "previous": body.Previous, "results": len(body.Results)})
		if x.Status != 200 {
			ended = fmt.Sprintf("status_%d", x.Status)
			break
		}
		count = body.Count
		for _, d := range body.Results {
			if seen[d.Name] {
				repeated = append(repeated, d.Name)
			}
			seen[d.Name] = true
			names = append(names, d.Name)
		}
		next = ""
		if body.Next != nil {
			next = *body.Next
		} else {
			ended = "null_next"
		}
	}
	return map[string]any{"limit": limit, "pages": pages, "count": count, "names": names, "repeated": repeated,
		"ended_at": ended}
}

// viaProxy reads the first page through the reverse proxy, which forwards
// the client's Host and sets X-Forwarded-Proto: https and X-Forwarded-Host,
// and records the next the product wrote there.
func (r *recorder) viaProxy(proxy string, limit int) exchange {
	return r.callURL("page_proxied", fmt.Sprintf("%s/api/dcim/devices/?limit=%d", proxy, limit))
}

// graphQLList asks for every device's name through each list shape a version
// might take — unpaged, and paged by the version's own arguments — and
// records how many names each returned, so a silent page cap shows, and the
// first device as returned, so the status value's spelling is on record.
func (r *recorder) graphQLList(product, path string, limit int) []map[string]any {
	var out []map[string]any
	for i, q := range graphQLListCandidates(product, limit) {
		x := r.call(fmt.Sprintf("graphql_list_%d", i), "POST", path, map[string]any{"query": q})
		var body struct {
			Data   map[string][]map[string]any `json:"data"`
			Errors []any                       `json:"errors"`
		}
		_ = json.Unmarshal(x.Body, &body)
		n := 0
		var first map[string]any
		for _, list := range body.Data {
			n += len(list)
			if first == nil && len(list) > 0 {
				first = list[0]
			}
		}
		out = append(out, map[string]any{"step": x.Step, "query": q, "status": x.Status, "names": n,
			"first": first, "errors": body.Errors})
	}
	return out
}

func graphQLListCandidates(product string, limit int) []string {
	if product == "nautobot" {
		return []string{
			`{ devices { name status { name } } }`,
			fmt.Sprintf(`{ devices(limit: %d, offset: 0) { name } }`, limit),
			fmt.Sprintf(`{ devices(limit: %d, offset: %d) { name } }`, limit, limit),
		}
	}
	return []string{
		`{ device_list { name status } }`,
		fmt.Sprintf(`{ device_list(pagination: {offset: 0, limit: %d}) { name } }`, limit),
		fmt.Sprintf(`{ device_list(pagination: {offset: %d, limit: %d}) { name } }`, limit, limit),
		fmt.Sprintf(`{ device_list(limit: %d, offset: 0) { name } }`, limit),
	}
}
