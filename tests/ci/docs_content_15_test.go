package ci

// Task 15: the stores and RFC 9887 pages. Each string is a fact the page owes its reader.
func init() {
	mustSay["operate/stores.md"] = append(mustSay["operate/stores.md"],
		"port49 store status", "port49 directory forget", "--bump-revision",
		"port49_store_directory_reachable", "/readyz", "staleness_ceiling", "logouts pending",
	)
	mustSay["operate/tls.md"] = append(mustSay["operate/tls.md"],
		"tls_name_clash", "identity_mismatch", "tls mutual-authentication certificate-id",
		"no_client_certificate", "ignoring(component)", "listen: none", "reference/decision-log.md#tls_outcome",
		"Unmeasured",
	)
}
