package l84

import (
	"fmt"
	"strings"
)

// Secret is one entry of a compose file's top-level secrets: a name and the host file it is read
// from. Every one is mounted at /run/secrets/<Name> in port49d and in the probe service.
type Secret struct{ Name, File string }

// MountDir is where Compose mounts a secret by default, and what the cell's key_secret_refs.file_dir
// names.
const MountDir = "/run/secrets"

// Override is the compose override file for L84 (docker compose -f compose.yaml -f override): the
// listed secrets on port49d, in the long syntax (uid "0", gid "65532", mode 0440, target the
// default path) or the short one, and a probe service on the image the stack's setup built, which
// reads the same mounts with stat. The long entry is the shape spec §15 L84 (b) names; the short
// is the documented 0444 form.
func Override(syntax string, secrets []Secret) (string, error) {
	if syntax != "long" && syntax != "short" {
		return "", fmt.Errorf("syntax %q is not long or short", syntax)
	}
	if len(secrets) == 0 {
		return "", fmt.Errorf("no secrets")
	}
	var entries, defs strings.Builder
	for _, s := range secrets {
		if s.Name == "" || strings.ContainsAny(s.Name, " /:\"'") || strings.ContainsAny(s.File, "\n\"") || !strings.HasPrefix(s.File, "/") {
			return "", fmt.Errorf("secret %q from %q: want a plain name and an absolute file", s.Name, s.File)
		}
		if syntax == "long" {
			fmt.Fprintf(&entries, "      - {source: %s, target: %s/%s, uid: \"0\", gid: \"65532\", mode: 0440}\n", s.Name, MountDir, s.Name)
		} else {
			fmt.Fprintf(&entries, "      - %s\n", s.Name)
		}
		fmt.Fprintf(&defs, "  %s: {file: \"%s\"}\n", s.Name, s.File)
	}
	return "services:\n  port49d:\n    secrets:\n" + entries.String() +
		"  probe:\n    profiles: [probe]\n    image: port49-setup:dev\n    pull_policy: never\n    entrypoint: [stat]\n    network_mode: none\n    secrets:\n" +
		entries.String() + "secrets:\n" + defs.String(), nil
}
