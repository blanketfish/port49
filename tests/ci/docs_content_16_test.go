package ci

// Task 16: the secrets and key-rotation pages. Each string is a fact the page owes its reader.
func init() {
	mustSay["operate/secrets.md"] = append(mustSay["operate/secrets.md"],
		"subPath", "agent-run-as-same-user", "defaultMode", "fsGroup",
		"ssl-cert", "key_secret_refs", "env_prefix", "file_dir", "secret_ref",
		"L82-kind.md", "L83-kind.md", "port49_key_secret_files_changed",
	)
	mustSay["admin/key-rotation.md"] = append(mustSay["admin/key-rotation.md"],
		"port49_key_secret_files_changed", "single_device", "init-issuer", "rotate-issuer",
		"forget-issuer", "encryption.previous", "port49 keys status", "port49_key_version_devices",
		"every 30 seconds", "Directory pins are never re-sealed", "ErrUnknownKey", "held_refused",
		"A store that holds pins can rotate once", "record=\"membership\"", "port49 directory forget",
		"Always give a new key a new id", "issuance: this broker's issuing CA", "reference/config/port49d.md",
	)
}
