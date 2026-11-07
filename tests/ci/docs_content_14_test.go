package ci

// Task 14: the broker and the agent, signing in, hardware keys. Each string is a fact the page owes its reader.
func init() {
	mustSay["operate/broker-and-agent.md"] = append(mustSay["operate/broker-and-agent.md"],
		"port49-broker", "agent.log", "XDG_RUNTIME_DIR", "max_session_age",
	)
	mustSay["operate/login.md"] = append(mustSay["operate/login.md"],
		"port49 ssh:", "--json", "accept-new", "known_hosts",
		"per_login_mfa_required", "broker_unavailable", "../reference/reason-codes.md",
		"| `port49 ssh` | 255 |",
		"| `port49 revoke` | 3 |",
		"| `port49 hwkey` | 1 |",
	)
	mustSay["operate/hardware-keys.md"] = append(mustSay["operate/hardware-keys.md"],
		"port49 hwkey setup", "port49 hwkey status", "roots: from broker", "roots: --roots", "--roots",
		"Unmeasured", "L60", "L63", "log in again", "install/clients.md",
	)
}
