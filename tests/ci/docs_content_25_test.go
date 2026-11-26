package ci

// Docs second pass, task 4: the reference and contributing pages that became the one home of a topic.
// Each string is a fact the page owes its reader.
func init() {
	mustSay["reference/requirements.md"] = append(mustSay["reference/requirements.md"],
		"10 ms", "load-beehive-gates.md", "port49_token_clock_skew", "node_timex_sync_status == 0",
		"lease_grace", "externalTrafficPolicy: Local", "etcd_disk_slow", "port49_accounting_spool_disk_slow",
		"3.4.24, 3.5.8 or 3.6", "## Clocks", "## etcd disk", "## Device source address",
	)
	mustSay["reference/client-commands.md"] = append(mustSay["reference/client-commands.md"],
		"--json", "per_login_mfa_required", "broker_unavailable", "reason-codes.md",
		"| `port49 ssh` | 255 |",
		"| `port49 revoke` | 3 |",
		"| `port49 hwkey` | 1 |",
	)
	mustSay["reference/health-checks.md"] = append(mustSay["reference/health-checks.md"],
		"--ready", "/healthz", "docker stack deploy", "service_healthy", "start_timeout",
		"`retries` from 3 to 6",
	)
	mustSay["contributing/deployment-design.md"] = append(mustSay["contributing/deployment-design.md"],
		"ProtectSystem=true", "CAP_NET_BIND_SERVICE", "3770", "make systemd-smoke", "make compose-smoke",
		"make kind-smoke",
	)
}
