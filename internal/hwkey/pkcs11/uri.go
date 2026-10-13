package pkcs11

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// URI is an RFC 7512 PKCS#11 URI: the attributes that pick a key, and the
// two query attributes port49 reads.
type URI struct {
	Token, Manufacturer, Serial, Model, Object, Type string
	ID                                               []byte
	SlotID                                           *uint
	ModulePath, PINSource                            string
}

// ParseURI reads s per RFC 7512 §2.3: "pkcs11:", then ";"-separated path
// attributes, then "?" and "&"-separated query attributes, values
// percent-decoded (id as bytes). A PIN is refused: it does not belong in a
// config file.
func ParseURI(s string) (URI, error) {
	var u URI
	rest, ok := strings.CutPrefix(s, "pkcs11:")
	if !ok {
		return u, errors.New("a PKCS#11 key reference starts with pkcs11:")
	}
	path, query, hasQuery := strings.Cut(rest, "?")
	seen := map[string]bool{}
	each := func(list, sep string, set func(name string, raw string) error) error {
		if list == "" {
			return nil
		}
		for _, a := range strings.Split(list, sep) {
			if a == "" {
				continue
			}
			name, raw, _ := strings.Cut(a, "=")
			if seen[name] {
				return fmt.Errorf("the attribute %s is given twice", name)
			}
			seen[name] = true
			if err := set(name, raw); err != nil {
				return err
			}
		}
		return nil
	}
	err := each(path, ";", func(name, raw string) error {
		v, err := percentDecode(raw)
		if err != nil {
			return fmt.Errorf("the attribute %s: %w", name, err)
		}
		switch name {
		case "token":
			u.Token = string(v)
		case "manufacturer":
			u.Manufacturer = string(v)
		case "serial":
			u.Serial = string(v)
		case "model":
			u.Model = string(v)
		case "object":
			u.Object = string(v)
		case "type":
			u.Type = string(v)
		case "id":
			u.ID = v
		case "slot-id":
			n, err := strconv.ParseUint(string(v), 10, 32)
			if err != nil {
				return fmt.Errorf("slot-id %q is not a slot number", v)
			}
			id := uint(n)
			u.SlotID = &id
		default:
			return fmt.Errorf("the attribute %s is not one port49 reads (token, manufacturer, serial, model, object, type, id, slot-id)", name)
		}
		return nil
	})
	if err != nil {
		return URI{}, err
	}
	if hasQuery {
		err = each(query, "&", func(name, raw string) error {
			if name == "pin-value" {
				// Refused before it is decoded: a bad escape's error would
				// quote PIN bytes.
				return errors.New("pin-value is refused: a PIN does not belong in a config file; use pin-source=file:///path or let `port49 login` ask it")
			}
			v, err := percentDecode(raw)
			if err != nil {
				return fmt.Errorf("the attribute %s: %w", name, err)
			}
			switch name {
			case "module-path":
				u.ModulePath = string(v)
			case "pin-source":
				u.PINSource = string(v)
			default:
				return fmt.Errorf("the attribute %s is not one port49 reads (module-path, pin-source)", name)
			}
			return nil
		})
		if err != nil {
			return URI{}, err
		}
	}
	switch {
	case u.ModulePath == "":
		return URI{}, errors.New("a PKCS#11 key reference needs module-path=/absolute/path/to/module.so")
	case !strings.HasPrefix(u.ModulePath, "/"):
		return URI{}, fmt.Errorf("module-path %q must be an absolute path", u.ModulePath)
	case len(u.ID) == 0 && u.Object == "":
		return URI{}, errors.New("a PKCS#11 key reference needs an id or object attribute to pick the key")
	}
	return u, nil
}

// percentDecode decodes %XX escapes; a malformed one is refused.
func percentDecode(s string) ([]byte, error) {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			out = append(out, s[i])
			continue
		}
		if i+2 >= len(s) {
			return nil, fmt.Errorf("bad percent escape at %q", s[i:])
		}
		hi, ok1 := unhex(s[i+1])
		lo, ok2 := unhex(s[i+2])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("bad percent escape %q", s[i:i+3])
		}
		out = append(out, hi<<4|lo)
		i += 2
	}
	return out, nil
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// percentEncode escapes everything but RFC 3986's unreserved characters and
// those in keep.
func percentEncode(b []byte, keep string) string {
	const hex = "0123456789ABCDEF"
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~', strings.IndexByte(keep, c) >= 0:
			sb.WriteByte(c)
		default:
			sb.WriteByte('%')
			sb.WriteByte(hex[c>>4])
			sb.WriteByte(hex[c&15])
		}
	}
	return sb.String()
}

// String is the canonical form, for messages. It carries the pin-source path
// and never a PIN: ParseURI refuses one.
func (u URI) String() string {
	var path []string
	add := func(name, v string) {
		if v != "" {
			path = append(path, name+"="+percentEncode([]byte(v), ""))
		}
	}
	add("token", u.Token)
	add("manufacturer", u.Manufacturer)
	add("serial", u.Serial)
	add("model", u.Model)
	add("object", u.Object)
	add("type", u.Type)
	if len(u.ID) > 0 {
		path = append(path, "id="+percentEncode(u.ID, ""))
	}
	if u.SlotID != nil {
		path = append(path, "slot-id="+strconv.FormatUint(uint64(*u.SlotID), 10))
	}
	var query []string
	if u.ModulePath != "" {
		query = append(query, "module-path="+percentEncode([]byte(u.ModulePath), "/"))
	}
	if u.PINSource != "" {
		query = append(query, "pin-source="+percentEncode([]byte(u.PINSource), "/:"))
	}
	s := "pkcs11:" + strings.Join(path, ";")
	if len(query) > 0 {
		s += "?" + strings.Join(query, "&")
	}
	return s
}
