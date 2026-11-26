package ci

// Task 14: signing in, the agent and hardware keys. Each string is a fact the page owes its reader. The
// exit-code and --json rows of the old login page live in docs_content_25_test.go
// (reference/client-commands.md).
func init() {
	mustSay["use/login.md"] = append(mustSay["use/login.md"],
		"agent.log", "XDG_RUNTIME_DIR", "max_session_age",
	)
	mustSay["use/connect.md"] = append(mustSay["use/connect.md"],
		"port49 ssh:", "accept-new", "known_hosts", "../reference/reason-codes.md",
	)
	mustSay["use/hardware-keys.md"] = append(mustSay["use/hardware-keys.md"],
		"port49 hwkey setup", "port49 hwkey status", "roots: from broker", "roots: --roots", "--roots",
		"Unmeasured", "L60", "L63", "log in again", "install-client.md",
	)
}
