package ci

// Task 13: Install, clients and versions. Each string is a fact the page owes its reader.
func init() {
	mustSay["operate/install/index.md"] = append(mustSay["operate/install/index.md"],
		"0755", "setgid", "init-revocations", "externalTrafficPolicy: Local",
		"with mode `0755`, owned by root, with no setgid bit and no file capabilities",
		"`broker.revocations_file` is used only by a single-process trial",
		"`port49-broker init-issuer`",
	)
	mustSay["operate/versions.md"] = append(mustSay["operate/versions.md"],
		"v0.1.0", "1.0.0", "--version",
		"| `v0.1.0` | The beta. |",
		"| `1.0.0` | The compatibility promise.",
	)
	mustSay["operate/install/clients.md"] = append(mustSay["operate/install/clients.md"],
		"--module", "libykcs11",
		"No path is probed.",
		"the libykcs11.dylib of your yubico-piv-tool install",
	)
}
