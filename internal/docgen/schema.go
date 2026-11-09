package docgen

import (
	"reflect"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/config"
)

// Key is one settable key of a schema. Path is dotted YAML: a map key is <name> and a list item is [].
type Key struct{ Path, Type string }

var (
	durationType    = reflect.TypeOf(time.Duration(0))
	timeType        = reflect.TypeOf(time.Time{})
	unmarshalerType = reflect.TypeOf((*yaml.Unmarshaler)(nil)).Elem()
)

// leafLabels names the type of a yaml.Unmarshaler that is not a duration. The decoder accepts
// several shapes for each, so the description says which.
var leafLabels = map[string]string{
	"stringList":  "string or list of string",
	"matchValue":  "string, list of string or comparison",
	"fileTestMFA": "none or mapping",
}

// refusedNames are keys a struct declares only so the loader can refuse them by name.
func refusedNames() map[string]bool {
	out := map[string]bool{"receipt_ttl": true}
	for _, k := range config.RemovedKeys() {
		out[k] = true
	}
	return out
}

// Keys lists the settable keys under root, in field order. It walks exported fields by their yaml tag,
// skips "-" and the keys the loader refuses by name, and reads a yaml.Unmarshaler as one leaf.
func Keys(root reflect.Type) []Key {
	var all, out []Key
	walk(root, "", map[reflect.Type]bool{}, refusedNames(), &all)
	for _, k := range all {
		if !identityKeyBelongs(k.Path) {
			continue
		}
		out = append(out, k)
	}
	return out
}

// Humans and machines share one verifier struct, and the loader refuses the other list's keys by name
// (internal/config/identity.go: checkOIDCVerifier, the x509, k8s and directory_password cases). Each list
// shows only the keys it takes, the first segment of the key under the item.
var (
	humansOnlyKeys = map[string]bool{"client_id": true, "principal_claim": true, "principal_domains": true, "scopes": true,
		"second_factor": true, "filter": true, "enrollment": true, "rate_limits": true, "totp_label": true}
	machinesOnlyKeys = map[string]bool{"spiffe_trust_domains": true, "audience": true, "clients": true, "cluster": true,
		"jwks": true, "namespaces": true, "directory": true}
	// sharedIdentityKeys are the keys both lists take (x509, oidc and k8s alike
	// on either side). Every verifier key is in exactly one of the three sets
	// (TestEveryIdentityVerifierKeyIsClassified).
	sharedIdentityKeys = map[string]bool{"type": true, "trust_anchor_file": true, "issuer": true, "algorithms": true,
		"ca_file": true}
)

func identityKeyBelongs(path string) bool {
	for list, other := range map[string]map[string]bool{
		"broker.identity.humans.[].":   machinesOnlyKeys,
		"broker.identity.machines.[].": humansOnlyKeys,
	} {
		if rest, ok := strings.CutPrefix(path, list); ok {
			first, _, _ := strings.Cut(rest, ".")
			return !other[first]
		}
	}
	return true
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

func walk(t reflect.Type, path string, active map[reflect.Type]bool, refused map[string]bool, out *[]Key) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if path != "" && isLeaf(t) {
		*out = append(*out, Key{path, leafLabel(path, t)})
		return
	}
	switch t.Kind() {
	case reflect.Struct:
		if active[t] {
			return
		}
		active[t] = true
		defer delete(active, t)
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name, inline := yamlName(f)
			if name == "-" || refused[name] {
				continue
			}
			if inline {
				walk(f.Type, path, active, refused, out)
				continue
			}
			walk(f.Type, join(path, name), active, refused, out)
		}
	case reflect.Map:
		if e := deref(t.Elem()); e.Kind() == reflect.Struct && !isLeaf(e) {
			walk(e, path+".<name>", active, refused, out)
			return
		}
		*out = append(*out, Key{path, typeLabel(path, t)})
	case reflect.Slice, reflect.Array:
		if e := deref(t.Elem()); e.Kind() == reflect.Struct && !isLeaf(e) {
			walk(e, path+".[]", active, refused, out)
			return
		}
		*out = append(*out, Key{path, typeLabel(path, t)})
	default:
		*out = append(*out, Key{path, typeLabel(path, t)})
	}
}

func deref(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

// yamlName is a field's key and whether its fields are inlined into the parent.
func yamlName(f reflect.StructField) (name string, inline bool) {
	parts := strings.Split(f.Tag.Get("yaml"), ",")
	for _, p := range parts[1:] {
		if p == "inline" {
			inline = true
		}
	}
	if parts[0] != "" {
		return parts[0], inline
	}
	return strings.ToLower(f.Name), inline
}

func isLeaf(t reflect.Type) bool {
	return t == durationType || t == timeType || reflect.PointerTo(t).Implements(unmarshalerType)
}

// isSecretRef reports a key that holds a secret reference. They are plain strings, so the name decides.
func isSecretRef(path string) bool {
	last := path[strings.LastIndex(path, ".")+1:]
	return last == "secret_ref" || strings.HasSuffix(last, "_secret_ref")
}

func leafLabel(path string, t reflect.Type) string {
	switch {
	case t == durationType, t.Kind() == reflect.Int64 && reflect.PointerTo(t).Implements(unmarshalerType):
		return "duration"
	case t == timeType:
		return "timestamp"
	}
	if l, ok := leafLabels[t.Name()]; ok {
		return l
	}
	return typeLabel(path, t)
}

func typeLabel(path string, t reflect.Type) string {
	t = deref(t)
	if isLeaf(t) {
		return leafLabel(path, t)
	}
	switch t.Kind() {
	case reflect.String:
		if isSecretRef(path) {
			return "secret reference"
		}
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "integer"
	case reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Slice, reflect.Array:
		return "list of " + typeLabel(path, t.Elem())
	case reflect.Map:
		return "map of " + typeLabel(path, t.Elem())
	}
	return t.Kind().String()
}
