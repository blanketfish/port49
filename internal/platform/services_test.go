package platform

import (
	"slices"
	"strings"
	"testing"
	"unicode"
)

// With branch M's switch on, a projected Junos device passes only with no
// management service but the CLI's: anything else under system services,
// an unknown name included, and REST, J-Web or extension-service at any
// hierarchy fail. Input not in the one form the check reads is refused, a
// group definition included, since a service behind one could be missed
// (plan 5b pre-flight C1).
func TestCheckServices(t *testing.T) {
	d := junosProjected(BitDeliveryLocalUserName)
	if !RPCServicesChecked(d) {
		t.Fatal("the switch is branch M's, on in 1.1.0: no wire deny binds a NETCONF RPC (L12-netconf-juniper_*.md)")
	}
	rpcServicesOff = false
	defer func() { rpcServicesOff = true }()
	if f, err := CheckServices(d, []byte("set system services netconf ssh\n")); f != nil || err != nil {
		t.Fatalf("off: %v %v", f, err)
	}
	rpcServicesOff = true
	clean := "set version 21.4R3.15\nset system host-name srx1\nset system services ssh root-login deny\n" +
		"set system services telnet\n" +
		"set interfaces fxp0 description \"rest of the lab\"\ndeactivate system services netconf\n"
	if f, err := CheckServices(d, []byte(clean)); len(f) != 0 || err != nil {
		t.Fatalf("clean: %+v %v", f, err)
	}
	for _, line := range []string{"set system services netconf ssh", "set system services xnm-ssl",
		"set system services rest http port 3000", "set system services web-management https interface fxp0",
		"set system services extension-service request-response grpc", "set system services outbound-ssh client c",
		"set system services frobnicate", "set services rest control", "set system services dhcp-local-server group g"} {
		f, err := CheckServices(d, []byte(clean+line+"\n"))
		if err != nil || len(f) != 1 || f[0].Text != line || !strings.Contains(f[0].Says, "only `system services ssh`") {
			t.Errorf("%s: %+v %v", line, f, err)
		}
	}
	for _, bad := range []string{
		clean + "set groups g system services rest\n",
		"system {\n    services {\n        rest;\n    }\n}\n",
		"",
	} {
		if _, err := CheckServices(d, []byte(bad)); err == nil || !strings.Contains(err.Error(), "display inheritance") {
			t.Errorf("%.40q: %v", bad, err)
		}
	}
	eos, _ := DialectFor("arista_eos")
	if RPCServicesChecked(eos) {
		t.Error("the check is a projected Junos adapter's")
	}
}

// The check is hunted for a way around it: a service written where a
// prefix check would not look, or hidden by a form the check cannot read.
// A statement that could enable a service is a finding; a capture that could
// hide one is refused (plan 5b Task 13a).
func TestCheckServicesBypasses(t *testing.T) {
	d := junosProjected(BitDeliveryLocalUserName)
	if !RPCServicesChecked(d) {
		t.Fatal("branch M's switch is off")
	}
	clean := "set version 23.4R2-S2.1\nset system host-name srx1\nset system services ssh\n"
	// Each is a finding, the line quoted back as it was read.
	for _, line := range []string{
		"set system services xnm-ssh",
		"set system services xnm-clear-text",
		"set system services netconf ssh port 830",
		"set system services netconf rfc-compliant",
		"set system services ftp",
		"set system services SSH",
		"set system services \"netconf\"",
		"set system services \"ssh telnet\"",
		"set \"system\" services netconf ssh",
		"set system \"services\" netconf ssh",
		"set logical-systems ls1 system services netconf ssh",
		"set tenants t1 system services netconf ssh",
		"set Logical-Systems ls1 system services netconf ssh",
		"set Tenants t1 system services netconf ssh",
		"set \"logical-systems\" ls1 system services netconf ssh",
		"set system services telnet netconf ssh",
		"set system services telnet xnm-clear-text",
		"set system services telnet \"connection-limit 5\"",
		"set logical-systems ls1 system services rest http",
		"set logical-systems \"ls1\" system services web-management http",
		"set system services ssh sftp-server extension-service",
		"set routing-options rest",
		"set services REST control",
		"set services \"rest\"",
		"set system services Web-Management http",
		"set system extension-service application file a.py",
		"set system services\tnetconf\tssh",
		"set system services netconf ssh\r",
		"  set system services netconf ssh",
	} {
		f, err := CheckServices(d, []byte(clean+line+"\n"))
		if err != nil || len(f) != 1 || !strings.Contains(f[0].Says, "only `system services ssh`") {
			t.Errorf("%q: %+v %v", line, f, err)
		}
	}
	// Each could hide a service behind something the check cannot resolve,
	// so the capture is refused, the capture named and no line quoted.
	for _, bad := range []string{
		"set groups g system services netconf ssh",
		"set \"groups\" g system services netconf ssh",
		"set logical-systems ls1 groups g system services netconf ssh",
		"set apply-groups g",
		"set system apply-groups g",
		"set logical-systems ls1 apply-groups g",
		"set system services apply-groups g",
		"inactive: netconf;",
		"netconf { ssh; }",
		"system { services { netconf ssh; } }",
		"activate system services netconf",
		"delete system services ssh",
		"insert system services x before y",
		"root@srx1> show configuration | display set",
		"set system services \"netconf",
		"set system services net​conf",
		"set system services netconf\x00 ssh",
		"set system services \xffnetconf",
		"set system services telnet\vset system services netconf ssh",
		"set system services telnet\vnetconf ssh",
		"set system services telnet\fnetconf ssh",
		"set system services telnet\u0085netconf",
		"set system services telnet\u2028netconf",
		"set system services telnet\u2029netconf",
		"set system services telnet\u00a0netconf",
		"set system services telnet\u3000netconf",
		"\vset system services netconf ssh",
		"set system services netconf ssh\v",
		"set Groups g system services netconf ssh",
		"set logical-systems ls1 Apply-Groups g",
	} {
		_, err := CheckServices(d, []byte(clean+bad+"\n"))
		if err == nil || !strings.Contains(err.Error(), ServicesCapture) {
			t.Errorf("%q: %v", bad, err)
			continue
		}
		// Apart from the capture it names and its own wording, the error
		// holds no word of the line.
		words := func(s string) []string {
			return strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsLetter(r) && r != '-' })
		}
		said := words(strings.ReplaceAll(err.Error(), ServicesCapture, ""))
		for _, w := range words(bad) {
			if len(w) > 3 && !slices.Contains([]string{"configuration", "display"}, w) && slices.Contains(said, w) {
				t.Errorf("%q: the error quotes %q: %v", bad, w, err)
			}
		}
	}
	// Neither a deactivate nor a protect enables anything, a terminal's
	// prompt and a ## line are not configuration, a group's deactivate is
	// what the capture's except leaves, and a value is not a keyword.
	for _, ok := range []string{
		"deactivate system services netconf",
		"protect system services",
		"deactivate groups g",
		"{master:0}",
		"{master:0}[edit]",
		"## Last commit: 2026-09-25 10:00:00 UTC by root",
		"",
		"   ",
		"set interfaces ge-0/0/0 description \"the rest web-management extension-service apply-groups\"",
		"set interfaces ge-0/0/0 description \"say \\\"rest\\\" twice\"",
		"set system services ssh root-login deny",
		"set system services ssh protocol-version v2",
		"set system services telnet connection-limit 5",
		"set system services telnet rate-limit 5",
		"set system services telnet authentication-order tacplus",
		"set system services telnet",
		"set system services ssh \"client-alive-count-max\" 3",
		"set system login class c allow-configuration-regexps \"system services .*\"",
		"set system apply-groups-except g",
	} {
		if f, err := CheckServices(d, []byte(clean+ok+"\n")); len(f) != 0 || err != nil {
			t.Errorf("%q: %+v %v", ok, f, err)
		}
	}
	// Under ssh only the transport's own options pass: sftp-server opens a
	// file-access subsystem no measured deny binds, tcp-forwarding a channel
	// to any port, and an option the list does not know fails, as does a
	// quoted value where the option belongs.
	for _, line := range []string{
		"set system services ssh sftp-server",
		"set system services ssh tcp-forwarding",
		"set system services ssh authorized-keys-command /var/tmp/k",
		"set system services ssh subsystem x",
		"set system services ssh frobnicate",
		"set system services ssh \"root-login deny\"",
		"set logical-systems ls1 system services ssh sftp-server",
	} {
		f, err := CheckServices(d, []byte(clean+line+"\n"))
		if err != nil || len(f) != 1 || !strings.Contains(f[0].Says, "only `system services ssh`") {
			t.Errorf("%q: %+v %v", line, f, err)
		}
	}
	for _, ok := range []string{"set system services ssh", "set system services ssh ciphers aes256-ctr",
		"set system services ssh macs hmac-sha2-256", "set system services ssh key-exchange ecdh-sha2-nistp256",
		"set system services ssh hostkey-algorithm no-ssh-dss", "set system services ssh rate-limit 10",
		"set system services ssh connection-limit 10", "set system services ssh no-tcp-forwarding",
		"set system services ssh no-passwords", "set system services ssh port 2222",
		"set system services ssh client-alive-interval 60", "set system services ssh max-sessions-per-connection 1",
		"set system services ssh rekey time-limit 60", "set system services ssh log-key-changes"} {
		if f, err := CheckServices(d, []byte(clean+ok+"\n")); len(f) != 0 || err != nil {
			t.Errorf("%q: %+v %v", ok, f, err)
		}
	}
	// A capture of nothing but a prompt holds no statement, and one of a
	// subtree — the system login port49 cares about — is not the whole
	// configuration, which begins with its set version line: a service
	// outside the subtree was never read (task 13a review I4).
	for _, partial := range []string{"{master:0}\n\n",
		"set system login class p49-readonly permissions view\nset system login user p49-readonly class p49-readonly\n",
		"set system services ssh\nset logical-systems ls1 version 21.4R3.15\n",
		"set system services ssh\ndeactivate version\n",
		"set system services ssh\nset version\n",
	} {
		if _, err := CheckServices(d, []byte(partial)); err == nil || !strings.Contains(err.Error(), ServicesCapture) {
			t.Errorf("%q: %v", partial, err)
		}
	}
	// A line longer than eachLine reads is an error, never a clean device.
	if _, err := CheckServices(d, []byte(clean+"set system host-name "+strings.Repeat("a", 2<<20)+"\n")); err == nil {
		t.Error("an over-long line read clean")
	}
	// Findings carry the line number the operator looks the line up by.
	f, err := CheckServices(d, []byte(clean+"deactivate system services netconf\nset system services netconf ssh\n"))
	if err != nil || len(f) != 1 || f[0].Line != 5 || f[0].Text != "set system services netconf ssh" {
		t.Errorf("line: %+v %v", f, err)
	}
}
