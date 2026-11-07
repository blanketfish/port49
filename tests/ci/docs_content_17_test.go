package ci

// Task 17: backup and restore. Each string is a fact the page owes the person reading it mid-restore.
func init() {
	mustSay["operate/backup-and-restore.md"] = append(mustSay["operate/backup-and-restore.md"],
		"restore-unspent", "token_spent", "port49_redemption_restore_unjudged", "--bump-revision", "restore.json",
		"marks.json", "witness.json", "enrollments.json", "issuing-ca.key", "revocations_file",
		"port49_store_restore_detected", "port49_store_restore_detected_timestamp_seconds",
		"the session store was restored from a snapshot", "every unspent token is purged",
		"port49_redemption_restored_refused_total", "port49_broker_mint_gate_closed",
		"etcdutl snapshot restore", "--mark-compacted", "init-enrollments", "export-enrollments",
		"port49 directory import", "revoke-offline.sh", "key-rotation.md", "L89-kind.md",
		"L35-restore-arista_eos.md", "!!! warning \"Unmeasured\"", "--8<-- \"deploy/helm/port49/examples/velero/README.md",
	)
}
