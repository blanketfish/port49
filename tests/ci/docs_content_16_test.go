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
		"every 30 seconds", "ErrUnknownKey", "held_refused",
		"record=\"membership\"", "port49 directory forget",
		"forget_principals", "no offline forget",
		"port49_directory_pins_sealed_previous", "port49_directory_pins_unopenable",
		"port49_directory_pins_reseal_last_complete_timestamp_seconds", "the re-seal of pins stopped",
		"port49_store_keyspace_held", "Rotating again",
		"Always give a new key a new id", "issuance: this broker's issuing CA", "reference/config/port49d.md",
	)
}
