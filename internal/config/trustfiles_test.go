package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// trustFileReaders is, for every config field that names a file granting trust (a CA, an anchor, roots, a
// bundle, a CRL issuer, intermediates), the source file whose reader of it goes through the fence: fence.Read
// (the policy-file rule: no link out of its directory, nothing group- or world-writable, owned by root or us,
// regular, bounded) or a secret rule. A writer to that directory would otherwise add a root, a client CA or
// a forged CRL issuer (spec §13 decision 54 ruling 16). A new field of this kind must be added here with its
// reader, or the test fails: it cannot skip the fence by being new.
var trustFileReaders = map[string]struct{ file, call string }{
	"BrokerConfig.ClientCAFile":            {"internal/broker/server.go", "fence.Read("},
	"identityVerifierYAML.TrustAnchorFile": {"internal/broker/server.go", "fence.Read("},
	"identityVerifierYAML.CAFile":          {"internal/port49d/permfa.go", "fence.Read("},
	"BrokerConfig.TLSCABundleFile":         {"internal/port49d/cabundle.go", "fence.Read("},
	"CertificateStatusCRL.IssuerFile":      {"internal/port49d/certstatus.go", "fence.Read("},
	"directoryYAML.CAFile":                 {"internal/directory/conn.go", "fence.Read("},
	"EtcdConfig.CAFile":                    {"internal/port49d/store.go", "fence.Read("},
	"InventoryServiceConfig.CAFile":        {"internal/inventory/client.go", "fence.Read("},
	"TLSListenerConfig.ClientCAFile":       {"internal/port49d/tlslistener.go", "fence.Read("},
	"TLSListenerConfig.IntermediatesFile":  {"internal/port49d/tlslistener.go", "fence.Read("},
	"perLoginMFAYAML.AttestationRootsFile": {"internal/port49d/permfa.go", "fence.Read("},
	"sourceYAML.CAFile":                    {"internal/sot/client.go", "fence.Read("},
	"fileConfig.ClientCAFile":              {"internal/broker/server.go", "fence.Read("},
}

var trustTag = regexp.MustCompile(`(^|_)(ca|anchor|roots|bundle|issuer|intermediates|crls?)(_|$)`)

func TestEveryTrustFileFieldIsReadThroughTheFence(t *testing.T) {
	root := filepath.Join("..", "..")
	found := map[string]bool{}
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
								if (strings.HasSuffix(tag, "_file") || strings.HasSuffix(tag, "_files")) && trustTag.MatchString(tag) {
									found[ts.Name.Name+"."+fl.Names[0].Name] = true
								}
							}
							return true
						})
					}
				}
			}
		}
	}
	if len(found) < 10 {
		t.Fatalf("found %d trust-file fields, want many more: the scan is broken", len(found))
	}
	var fields []string
	for k := range found {
		fields = append(fields, k)
	}
	sort.Strings(fields)
	for _, k := range fields {
		r, ok := trustFileReaders[k]
		if !ok {
			t.Errorf("%s names a file that grants trust and is not in trustFileReaders: read it through fence.Read "+
				"(or a ReadSecret/ReadOwn path) and add its reader here", k)
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, r.file))
		if err != nil {
			t.Errorf("%s: %v", k, err)
			continue
		}
		if !strings.Contains(string(b), r.call) {
			t.Errorf("%s is read in %s, which no longer calls %s", k, r.file, r.call)
		}
	}
	// A table entry for a field that is gone is stale.
	for k := range trustFileReaders {
		if !found[k] {
			t.Errorf("%s is in trustFileReaders and not in the config structs: remove it", k)
		}
	}
}
