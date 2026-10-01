package sot

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The profiles: one per product and the releases whose answers L27 and L30
// recorded as alike.
const (
	NetBox37   = "netbox_3_7"
	NetBox4    = "netbox_4"
	Nautobot16 = "nautobot_1_6"
	// Nautobot2 is 2.x and 3.x: 3.2.6 answered every L27 question as 2.4.43
	// did, less the device fields cluster and software_image_files, which no
	// profile reads (L30).
	Nautobot2 = "nautobot_2"
)

// paging is how a profile's GraphQL list pages (L30).
type paging int

const (
	pageNone   paging = iota // NetBox 3.7.8: no shape tried; the whole list in one answer
	pageNested               // NetBox 4.7.1: pagination: {offset, limit}
	pageArgs                 // every Nautobot: limit, offset
)

// field is where one fact sits in a device, as a path of object keys, over
// GraphQL and over REST. nil is a fact that API does not give on the profile.
type field struct{ graphql, rest []string }

func (f field) over(api string) []string {
	if api == "rest" {
		return f.rest
	}
	return f.graphql
}

func both(path ...string) field { return field{path, path} }

func graphqlOnly(path ...string) field { return field{graphql: path} }

// Profile is how one product's releases are read: the GraphQL endpoint and
// list, how it pages, whether REST needs ?depth=1, where status, tags and
// custom fields sit, and the map's vocabulary — the fields L27 and L30
// recorded, and no others (decision 31).
type Profile struct {
	Name, Product string

	graphqlPath  string
	list         string
	paging       paging
	depthOne     bool
	tagKey       string
	status       field
	customFields field
	fields       map[string]field
	defaultMap   map[string]string
}

var netboxFields = map[string]field{
	"site.slug":     both("site", "slug"),
	"role.slug":     both("role", "slug"),
	"platform.slug": both("platform", "slug"),
}

var profiles = map[string]Profile{
	// L27, L30: NetBox 3.7.8 takes role over GraphQL (REST reads device_role
	// beside it), custom_fields as an object, status as the upper-case enum
	// name over GraphQL ("ACTIVE") and {value, label} over REST; its GraphQL
	// list took no paging shape tried and returned all 120.
	NetBox37: {Name: NetBox37, Product: "netbox", graphqlPath: "/graphql/", list: "device_list", paging: pageNone,
		tagKey: "slug", status: field{[]string{"status"}, []string{"status", "value"}},
		customFields: both("custom_fields"), fields: netboxFields,
		defaultMap: map[string]string{"platform": "platform.slug", "site": "site.slug", "role": "role.slug"}},
	// L27, L30: NetBox 4.7.1 as 3.7.8, status "active" over GraphQL, paged
	// by pagination: {offset, limit}.
	NetBox4: {Name: NetBox4, Product: "netbox", graphqlPath: "/graphql/", list: "device_list", paging: pageNested,
		tagKey: "slug", status: field{[]string{"status"}, []string{"status", "value"}},
		customFields: both("custom_fields"), fields: netboxFields,
		defaultMap: map[string]string{"platform": "platform.slug", "site": "site.slug", "role": "role.slug"}},
	// L27, L30: Nautobot 1.6.32 takes device_role and site; network_driver
	// over GraphQL only; _custom_field_data over GraphQL, custom_fields over
	// REST; status {name} over GraphQL, {value, label} over REST.
	Nautobot16: {Name: Nautobot16, Product: "nautobot", graphqlPath: "/api/graphql/", list: "devices", paging: pageArgs,
		tagKey: "slug", status: field{[]string{"status", "name"}, []string{"status", "value"}},
		customFields: field{[]string{"_custom_field_data"}, []string{"custom_fields"}},
		fields: map[string]field{
			"site.slug":               both("site", "slug"),
			"role.slug":               both("device_role", "slug"),
			"platform.slug":           both("platform", "slug"),
			"platform.network_driver": graphqlOnly("platform", "network_driver"),
		},
		defaultMap: map[string]string{"platform": "platform.network_driver", "site": "site.slug", "role": "role.slug"}},
	// L27, L30: Nautobot 2.4.43 and 3.2.6 take role and location, no slug;
	// REST names a related object only at ?depth=1; status {name} both ways.
	Nautobot2: {Name: Nautobot2, Product: "nautobot", graphqlPath: "/api/graphql/", list: "devices", paging: pageArgs,
		depthOne: true, tagKey: "name", status: both("status", "name"),
		customFields: field{[]string{"_custom_field_data"}, []string{"custom_fields"}},
		fields: map[string]field{
			"location.name":           both("location", "name"),
			"role.name":               both("role", "name"),
			"platform.name":           both("platform", "name"),
			"platform.network_driver": both("platform", "network_driver"),
		},
		defaultMap: map[string]string{"platform": "platform.network_driver", "site": "location.name", "role": "role.name"}},
}

// paths is the profile's vocabulary, sorted, for an error that names it.
func (p Profile) paths() []string {
	out := make([]string, 0, len(p.fields))
	for path := range p.fields {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// customKey is a custom field's key as a map path may name it.
var customKey = regexp.MustCompile(`^custom_fields\.[A-Za-z0-9_]{1,64}$`)

// ValidPath is whether some profile can read path: a field one records,
// status, or custom_fields.<key>. Which profile reads it is known only once
// the release is (Mapping.check).
func ValidPath(path string) bool {
	if path == "status" || customKey.MatchString(path) {
		return true
	}
	for _, p := range profiles {
		if _, ok := p.fields[path]; ok {
			return true
		}
	}
	return false
}

// KnownProfile is whether name is one of product's profiles.
func KnownProfile(product, name string) bool {
	p, ok := profiles[name]
	return ok && p.Product == product
}

// Version is a product's release, as /api/status/ gives it.
type Version struct {
	Product, Text string
	Major, Minor  int
}

// versionShape is a release: digits, a dot, digits, an optional patch and
// suffix. Anything else is not printed.
var versionShape = regexp.MustCompile(`^(\d{1,4})\.(\d{1,4})(\.\d{1,4})?([-+][0-9A-Za-z.+-]{0,32})?$`)

func productName(product string) string {
	if product == "nautobot" {
		return "Nautobot"
	}
	return "NetBox"
}

// versionOf is the release in /api/status/'s body: netbox-version or
// nautobot-version, never Api-Version, which Nautobot 1.6 sets to 1.2 (L27).
func versionOf(status map[string]any, product string) (Version, error) {
	other := "nautobot"
	if product == "nautobot" {
		other = "netbox"
	}
	raw, ok := status[product+"-version"]
	if !ok {
		if _, isOther := status[other+"-version"]; isOther {
			return Version{}, fmt.Errorf("url answers as %s, and the source's type is %s", productName(other), product)
		}
		return Version{}, fmt.Errorf("/api/status/ names no %s-version; is url the %s it should be?", product,
			productName(product))
	}
	text, _ := raw.(string)
	m := versionShape.FindStringSubmatch(text)
	if m == nil {
		return Version{}, fmt.Errorf("/api/status/ gives a %s-version that is not a release number "+
			"(want <major>.<minor>[.<patch>][-suffix])", product)
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return Version{Product: product, Text: text, Major: major, Minor: minor}, nil
}

// measured is the minor releases L27 and L30 recorded, by product.
var measured = map[string][]string{"netbox": {"3.7", "4.7"}, "nautobot": {"1.6", "2.4", "3.2"}}

func isMeasured(v Version) bool {
	for _, m := range measured[v.Product] {
		if m == fmt.Sprintf("%d.%d", v.Major, v.Minor) {
			return true
		}
	}
	return false
}

func measuredList(product string) string {
	out := make([]string, len(measured[product]))
	for i, m := range measured[product] {
		out[i] = productName(product) + " " + m
	}
	return strings.Join(out, ", ")
}

// pick is v's profile by major and minor, as L27 and L30 measured, and false
// for a major no lab run measured.
func pick(v Version) (string, bool) {
	switch {
	case v.Product == "netbox" && v.Major == 3 && v.Minor == 7:
		return NetBox37, true
	case v.Product == "netbox" && v.Major == 4:
		return NetBox4, true
	case v.Product == "nautobot" && v.Major == 1 && v.Minor == 6:
		return Nautobot16, true
	case v.Product == "nautobot" && (v.Major == 2 || v.Major == 3):
		return Nautobot2, true
	}
	return "", false
}

// Detect picks v's profile and says whether a lab run measured that minor
// with that profile. override, a profile name, is taken as given (spec §10:
// "an explicit override available"); it is measured only when it is the
// profile detection would pick.
func Detect(v Version, override string) (Profile, bool, error) {
	auto, ok := pick(v)
	if override != "" {
		if !KnownProfile(v.Product, override) {
			return Profile{}, false, fmt.Errorf("profile %s is not a %s profile", override, v.Product)
		}
		return profiles[override], ok && auto == override && isMeasured(v), nil
	}
	if !ok {
		return Profile{}, false, fmt.Errorf("%s %s is a release no lab run measured (spec §15 L27, L30: %s); set profile "+
			"to read it with a measured release's fields, at your own risk", productName(v.Product), v.Text,
			measuredList(v.Product))
	}
	return profiles[auto], isMeasured(v), nil
}
