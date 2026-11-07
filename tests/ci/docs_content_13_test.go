package ci

// Task 13: Install, clients and versions. Each string is a fact the page owes its reader.
func init() {
	mustSay["operate/install/index.md"] = append(mustSay["operate/install/index.md"],
		"0755", "setgid", "init-revocations", "externalTrafficPolicy: Local",
	)
	mustSay["operate/versions.md"] = append(mustSay["operate/versions.md"],
		"v0.1.0", "1.0.0", "--version",
	)
	mustSay["operate/install/clients.md"] = append(mustSay["operate/install/clients.md"],
		"--module", "libykcs11",
	)
}
