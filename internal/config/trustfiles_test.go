package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Every config field that names a file is classified here, so a new one cannot skip the fence by being
// named something the test did not expect (a keyword list would pass `cacert_file`). A field is one of:
//
//   - trust: it names what the process trusts (a CA, an anchor, roots, a bundle, a CRL issuer). Read through
//     fence.Read (the policy-file rule: no link out of its directory, nothing group- or world-writable, owned
//     by root or us, regular, bounded), because a writer to its directory would add a root (spec §13
//     decision 54 ruling 16).
//   - policy: policy, inventory and verification keys; also fence.Read / fence.ReadVerifyKeys.
//   - secret: a private key, keytab or signing key; read under keyfile.ReadSecret / LoadX509KeyPair /
//     LoadEd25519 (the secret-file rule) or ReadOwn.
//   - other: with the reason it needs no fence.
//
// trust, policy and secret name the source file that reads it and the call that must still appear there.
type fileClass struct {
	class, file, call, reason string
}

func trust(file string) fileClass { return fileClass{class: "trust", file: file, call: "fence.Read("} }
func policy(file, call string) fileClass {
	return fileClass{class: "policy", file: file, call: call}
}
func secret(file, call string) fileClass {
	return fileClass{class: "secret", file: file, call: call}
}
func other(reason string) fileClass { return fileClass{class: "other", reason: reason} }

const publicCert = "a public certificate: replacing it can break TLS, not add trust"

var fileFields = map[string]fileClass{
	// trust
	"BrokerConfig.ClientCAFile":            trust("internal/broker/server.go"),
	"fileConfig.ClientCAFile":              trust("internal/broker/server.go"),
	"identityVerifierYAML.TrustAnchorFile": trust("internal/broker/server.go"),
	"identityVerifierYAML.CAFile":          trust("internal/port49d/permfa.go"),
	"perLoginMFAYAML.AttestationRootsFile": trust("internal/port49d/permfa.go"),
	"BrokerConfig.TLSCABundleFile":         trust("internal/port49d/cabundle.go"),
	"CertificateStatusCRL.IssuerFile":      trust("internal/port49d/certstatus.go"),
	"directoryYAML.CAFile":                 trust("internal/directory/conn.go"),
	"EtcdConfig.CAFile":                    trust("internal/port49d/store.go"),
	"InventoryServiceConfig.CAFile":        trust("internal/inventory/client.go"),
	"sourceYAML.CAFile":                    trust("internal/sot/client.go"),
	"TLSListenerConfig.ClientCAFile":       trust("internal/port49d/tlslistener.go"),
	"TLSListenerConfig.IntermediatesFile":  trust("internal/port49d/tlslistener.go"),
	// policy
	"BrokerConfig.PolicyFile":               policy("internal/port49d/policyfile.go", "fence.Read("),
	"fileConfig.PolicyFile":                 policy("internal/inventory/sync.go", "fence.Read("),
	"fileConfig.InventoryFile":              policy("internal/port49d/policyfile.go", "fence.Read("),
	"fileConfig.VerifyKeyFiles":             policy("cmd/port49-inventory/main.go", "fence.ReadVerifyKeys("),
	"InventoryServiceConfig.VerifyKeyFiles": policy("internal/config/config.go", "fence.ReadVerifyKeys("),
	// secret
	"bindYAML.KeytabFile":               secret("internal/directory/conn.go", "keyfile.ReadSecret("),
	"bindYAML.TLSKeyFile":               secret("internal/directory/conn.go", "keyfile.LoadX509KeyPair("),
	"BrokerConfig.TLSKeyFile":           secret("internal/port49d/main.go", "keyfile.LoadX509KeyPair("),
	"EtcdIdentity.KeyFile":              secret("internal/port49d/store.go", "keyfile.LoadX509KeyPair("),
	"fileConfig.TLSKeyFile":             secret("internal/broker/server.go", "keyfile.LoadX509KeyPair("),
	"fileConfig.WebhookTLSKeyFile":      secret("cmd/port49-inventory/main.go", "keyfile.LoadX509KeyPair("),
	"fileConfig.SigningKeyFile":         secret("cmd/port49-inventory/main.go", "keyfile.LoadEd25519("),
	"InventoryServiceConfig.TLSKeyFile": secret("internal/inventory/client.go", "keyfile.LoadX509KeyPair("),
	"TLSListenerConfig.KeyFile":         secret("internal/port49d/tlslistener.go", "keyfile.ReadSecret("),
	// other
	"bindYAML.TLSCertFile":               other(publicCert),
	"BrokerConfig.TLSCertFile":           other(publicCert),
	"EtcdIdentity.CertFile":              other(publicCert),
	"fileConfig.TLSCertFile":             other(publicCert),
	"fileConfig.WebhookTLSCertFile":      other(publicCert),
	"InventoryServiceConfig.TLSCertFile": other(publicCert),
	"TLSListenerConfig.CertFile":         other(publicCert),
	"BrokerConfig.RevocationsFile":       other("port49d's own state file, written by port49d under its own flock and owner check, not an operator input"),
	"LabConfig.FaultFile":                other("lab-only fault injection, refused outside a lab build"),
	"LabConfig.SeedTokenFile":            other("lab-only seed tokens, refused outside a lab build"),
}

func TestEveryFileFieldIsClassified(t *testing.T) {
	root := filepath.Join("..", "..")
	found := map[string]string{}
	for _, dir := range []string{"internal/config", "internal/inventory"} {
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, filepath.Join(root, dir), func(fi os.FileInfo) bool {
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range pkgs {
			for _, f := range p.Files {
				for _, d := range f.Decls {
					g, ok := d.(*ast.GenDecl)
					if !ok {
						continue
					}
					for _, sp := range g.Specs {
						ts, ok := sp.(*ast.TypeSpec)
						if !ok {
							continue
						}
						ast.Inspect(ts.Type, func(n ast.Node) bool {
							st, ok := n.(*ast.StructType)
							if !ok {
								return true
							}
							for _, fl := range st.Fields.List {
								if fl.Tag == nil || len(fl.Names) == 0 {
									continue
								}
								tag := strings.Split(reflect.StructTag(strings.Trim(fl.Tag.Value, "`")).Get("yaml"), ",")[0]
								if strings.HasSuffix(tag, "_file") || strings.HasSuffix(tag, "_files") {
									found[ts.Name.Name+"."+fl.Names[0].Name] = tag
								}
							}
							return true
						})
					}
				}
			}
		}
	}
	if len(found) < 30 {
		t.Fatalf("found %d file fields, want about 40: the scan is broken", len(found))
	}
	var fields []string
	for k := range found {
		fields = append(fields, k)
	}
	sort.Strings(fields)
	for _, k := range fields {
		c, ok := fileFields[k]
		if !ok {
			t.Errorf("%s (%s) is a file field with no classification: read it through fence.Read (a trust or policy "+
				"file) or keyfile (a secret), or say why it needs neither, and add it to fileFields", k, found[k])
			continue
		}
		switch c.class {
		case "other":
			if c.reason == "" {
				t.Errorf("%s is classified other with no reason", k)
			}
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, c.file))
		if err != nil {
			t.Errorf("%s: %v", k, err)
			continue
		}
		if !strings.Contains(string(b), c.call) {
			t.Errorf("%s (%s) is read in %s, which no longer calls %s", k, c.class, c.file, c.call)
		}
	}
	for k := range fileFields {
		if _, ok := found[k]; !ok {
			t.Errorf("%s is in fileFields and not in the config structs: remove it", k)
		}
	}
}
