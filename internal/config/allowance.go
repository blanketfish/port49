package config

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rhwendt/port49/internal/secretref"
)

// keyPath is a path port49d.yaml names that holds key material; dir marks one
// that is a directory whose contents are key material.
type keyPath struct {
	path string
	dir  bool
}

// secretsApart refuses a secret or key material port49d.yaml names that a
// policy could name too (decision 53 ruling 12; re-review N1): the policy
// could put it in force as a device key. Each secret_ref is held to Allows,
// and a file: one to file_dir by path as well; each key file, and the
// broker's state directory, to file_dir by path.
func secretsApart(c Config) error {
	allow := c.KeySecretRefs
	refs := ownSecretRefs(c)
	for _, at := range sortedKeyPaths(refs) {
		text := refs[at]
		ref, err := secretref.Parse(text)
		if err != nil {
			continue // its own check refuses it
		}
		if allow.Allows(ref) || ref.Scheme == secretref.SchemeFile && pathWithin(ref.Name, allow.FileDir) {
			return fmt.Errorf("config: %s %s is inside key_secret_refs (%s), so a policy could name it as a "+
				"device key; name it outside (decision 53 ruling 12)", at, text, allow)
		}
	}
	paths := ownKeyPaths(c)
	for _, at := range sortedKeyPaths(paths) {
		p := paths[at]
		if pathWithin(p.path, allow.FileDir) || p.dir && pathWithin(allow.FileDir, p.path) {
			return fmt.Errorf("config: %s %s overlaps key_secret_refs.file_dir %s, so a policy could name the "+
				"key material there as a device key; keep them apart (decision 53 ruling 12)", at, p.path,
				allow.FileDir)
		}
	}
	return nil
}

// ownSecretRefs is each secret_ref port49d.yaml names, by its key path: the
// encryption keys and the directory bind password.
func ownSecretRefs(c Config) map[string]string {
	out := map[string]string{}
	if c.encCurrent.SecretRef != "" {
		out["encryption.current.secret_ref"] = c.encCurrent.SecretRef
	}
	if c.encPrevious.SecretRef != "" {
		out["encryption.previous.secret_ref"] = c.encPrevious.SecretRef
	}
	if c.Broker != nil && c.Broker.Directory != nil && c.Broker.Directory.Bind.PasswordRef != "" {
		out["broker.directory.bind.password_secret_ref"] = c.Broker.Directory.Bind.PasswordRef
	}
	return out
}

// ownKeyPaths is each key file and key directory port49d.yaml names, by its
// key path. Empty paths are skipped.
func ownKeyPaths(c Config) map[string]keyPath {
	out := map[string]keyPath{}
	add := func(at, path string, dir bool) {
		if path != "" {
			out[at] = keyPath{path, dir}
		}
	}
	if c.TLSListener != nil {
		add("tls_listener.key_file", c.TLSListener.KeyFile, false)
	}
	if c.InventoryService != nil {
		add("inventory_service.tls_key_file", c.InventoryService.TLSKeyFile, false)
	}
	if b := c.Broker; b != nil {
		add("broker.tls_key_file", b.TLSKeyFile, false)
		if b.Directory != nil {
			add("broker.directory.bind.tls_key_file", b.Directory.Bind.TLSKeyFile, false)
			add("broker.directory.bind.keytab_file", b.Directory.Bind.KeytabFile, false)
		}
		add("broker state directory", BrokerStateDir(b), true)
	}
	for name, s := range map[string]StoreConfig{"stores.directory": c.Stores.Directory, "stores.session": c.Stores.Session} {
		if s.Etcd == nil {
			continue
		}
		add(name+".etcd.daemon.key_file", s.Etcd.Daemon.KeyFile, false)
		if s.Etcd.Broker != nil {
			add(name+".etcd.broker.key_file", s.Etcd.Broker.KeyFile, false)
		}
	}
	return out
}

func sortedKeyPaths[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pathWithin reports whether path is dir or below it, compared as written and
// again with links resolved, as fence.ReadSecret resolves them: a link
// either way must not hide an overlap.
func pathWithin(path, dir string) bool {
	return under(abs(path), abs(dir)) || under(resolved(path), resolved(dir))
}

// under reports whether path is dir or below it, on clean paths.
func under(path, dir string) bool {
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}

// abs is the clean absolute path, kept as written when it cannot be made one.
func abs(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

// resolved is p with its links followed; when p does not exist yet (a
// file_dir the agent has not created) its nearest existing ancestor is
// resolved and the rest joined on.
func resolved(p string) string {
	p = abs(p)
	rest := ""
	for cur := p; ; cur = filepath.Dir(cur) {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(r, rest)
		}
		if filepath.Dir(cur) == cur {
			return p
		}
		rest = filepath.Join(filepath.Base(cur), rest)
	}
}
