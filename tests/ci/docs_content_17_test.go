package ci

// Task 17: backup and restore. Each string is a fact the page owes the person reading it mid-restore.
func init() {
	mustSay["operate/backup-and-restore.md"] = append(mustSay["operate/backup-and-restore.md"],
		"restore-unspent", "token_spent", "--bump-revision", "restore.json",
		"marks.json", "witness.json", "enrollments.json", "issuing-ca.key", "revocations_file",
		"every unspent token is purged",
		"port49_redemption_restored_refused_total",
		"etcdutl snapshot restore", "--mark-compacted", "init-enrollments", "export-enrollments",
		"port49 directory import", "revoke-offline.sh", "key-rotation.md",
		"directory holding `broker.revocations_file`", "no bundle has been judged on this keyspace",
		"Check `broker.policy_file` on every broker host", "suspend every GitOps controller",
		"restart every port49d only after", "the key current at export time",
		"L35-restore-arista_eos.md", "!!! warning \"Unmeasured\"",
	)
	mustSay["operate/helm/velero.md"] = append(mustSay["operate/helm/velero.md"],
		"--8<-- \"deploy/helm/port49/examples/velero/README.md", "L89-kind.md",
	)
	// The lines and metrics a restore leaves moved to the 3am index with their entry.
	mustSay["operate/troubleshooting/index.md"] = append(mustSay["operate/troubleshooting/index.md"],
		"port49_redemption_restore_unjudged", "port49_store_restore_detected",
		"port49_store_restore_detected_timestamp_seconds", "the session store was restored from a snapshot",
		"port49_broker_mint_gate_closed",
	)
}
