package ci

// Task 13: Install, clients and versions. Each string is a fact the page owes its reader.
func init() {
	mustSay["operate/deploy/index.md"] = append(mustSay["operate/deploy/index.md"],
		"externalTrafficPolicy: Local", "`port49-broker init-issuer`", "port49-broker",
	)
	// The memory-store rows live on operate/stores.md with the section that holds them (Task 10a).
	mustSay["operate/stores.md"] = append(mustSay["operate/stores.md"],
		"init-revocations",
		"`broker.revocations_file` itself",
	)
	mustSay["operate/versions.md"] = append(mustSay["operate/versions.md"],
		"v0.1.0", "1.0.0", "--version",
		"| `v0.1.0` | The beta. |",
		"| `1.0.0` | The compatibility promise.",
	)
	mustSay["use/install-client.md"] = append(mustSay["use/install-client.md"],
		"0755", "setgid",
		"with mode `0755`, owned by root, with no setgid bit and no file capabilities",
		"--module", "libykcs11",
		"No path is probed.",
		"the libykcs11.dylib of your yubico-piv-tool install",
	)
}
