package ci

// Task 21: the device pages. Each string is a fact the page owes the operator.
func init() {
	mustSay["admin/devices/nokia-sr-linux.md"] = append(mustSay["admin/devices/nokia-sr-linux.md"],
		"sends no command authorization", "priv-lvl-authorization true", "services [ cli ]",
	)
	mustSay["admin/devices/juniper-junos.md"] = append(mustSay["admin/devices/juniper-junos.md"],
		"authentication-order tacplus", "server_names", "sni_mismatch", "Unmeasured",
	)
	mustSay["admin/devices/cisco-ios-xr.md"] = append(mustSay["admin/devices/cisco-ios-xr.md"],
		"domain name", "policy-platforms.yaml",
	)
	mustSay["admin/devices/cisco-ios-xe.md"] = append(mustSay["admin/devices/cisco-ios-xe.md"],
		"break-glass",
	)
	mustSay["admin/devices/cisco-nx-os.md"] = append(mustSay["admin/devices/cisco-nx-os.md"],
		"single-connect",
	)
}
