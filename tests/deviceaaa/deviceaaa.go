// Package deviceaaa renders the reference AAA configurations in deploy/device-aaa. The lab
// (L88) pushes Render's output unchanged, so it is exactly what an operator would paste:
// the commands, with the files' comments and blank lines left out.
package deviceaaa

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// Values fills a reference configuration's placeholders.
type Values struct {
	Servers         []string // the two port49 server addresses
	Port            int      // the plain TACACS+ port; the references use 49, so 0 or 49
	SourceInterface string   // EOS, IOS XE, NX-OS and XR pin their source by interface
	SourceAddress   string   // Junos and SR Linux pin it by address
	MgmtVRF         string   // the management VRF or routing instance TACACS+ runs in
	BreakGlass      string
	TLSPort         int
	ServerName      string // this device's own name, which its certificate carries (not port49's)
	CertID          string // the device certificate's trustpoint or certificate id
}

// ext is each platform's file extension.
var ext = map[string]string{
	"arista_eos": ".cfg", "cisco_iosxe": ".cfg", "cisco_nxos": ".cfg", "cisco_iosxr": ".cfg",
	"juniper_junos": ".set", "nokia_srlinux": ".cli",
}

// Placeholders is the closed set the reference files may contain.
func Placeholders() []string {
	return []string{"<PORT49_1>", "<PORT49_2>", "<KEY>", "<SOURCE_INTERFACE>", "<SOURCE_ADDRESS>", "<MGMT_VRF>",
		"<BREAKGLASS_USER>", "<TLS_PORT>", "<SERVER_NAME>", "<CERT_ID>"}
}

var leftover = regexp.MustCompile(`<[^<>\s]*>`)

// Render reads deploy/device-aaa/<platform>[-tls].<ext> and returns its command lines with
// the values substituted. transport is "tcp" or "tls". key is substituted last and never
// appears in an error. A placeholder left over, or a value the file needs and v lacks, is
// an error.
func Render(platform, transport string, v Values, key string) ([]string, error) {
	e, ok := ext[platform]
	if !ok {
		return nil, fmt.Errorf("deviceaaa: no reference for platform %q", platform)
	}
	name := platform + e
	switch transport {
	case "tcp":
	case "tls":
		name = platform + "-tls" + e
	default:
		return nil, fmt.Errorf("deviceaaa: transport %q is neither tcp nor tls", transport)
	}
	if v.Port != 0 && v.Port != 49 {
		return nil, fmt.Errorf("deviceaaa: the references use TACACS+ port 49, not %d", v.Port)
	}
	if len(v.Servers) != 2 {
		return nil, fmt.Errorf("deviceaaa: %d servers, want 2", len(v.Servers))
	}
	if v.Servers[0] == "" || v.Servers[0] == v.Servers[1] {
		return nil, errors.New("deviceaaa: the two servers must be set and distinct")
	}
	for _, f := range []string{v.Servers[0], v.Servers[1], v.SourceInterface, v.SourceAddress, v.MgmtVRF, v.BreakGlass,
		v.ServerName, v.CertID} {
		if strings.ContainsAny(f, " \t\r\n<>\"") {
			return nil, fmt.Errorf("deviceaaa: the value %q is not a single token", f)
		}
	}
	if strings.ContainsAny(key, "\r\n") {
		return nil, errors.New("deviceaaa: the key holds a line break")
	}
	if key == "" && transport == "tcp" {
		return nil, errors.New("deviceaaa: an empty key")
	}
	body, err := os.ReadFile(filepath.Join(repoRoot(), "deploy", "device-aaa", name))
	if err != nil {
		return nil, fmt.Errorf("deviceaaa: %w", err)
	}
	sub := strings.NewReplacer(
		"<PORT49_1>", v.Servers[0], "<PORT49_2>", v.Servers[1],
		"<SOURCE_INTERFACE>", v.SourceInterface, "<SOURCE_ADDRESS>", v.SourceAddress,
		"<MGMT_VRF>", v.MgmtVRF, "<BREAKGLASS_USER>", v.BreakGlass,
		"<TLS_PORT>", strconv.Itoa(v.TLSPort), "<SERVER_NAME>", v.ServerName, "<CERT_ID>", v.CertID)
	var out []string
	for _, l := range strings.Split(string(body), "\n") {
		if t := strings.TrimSpace(l); t == "" || strings.HasPrefix(t, "!") || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.Contains(l, "<TLS_PORT>") && v.TLSPort == 0 {
			return nil, fmt.Errorf("deviceaaa: %s needs a TLS port", name)
		}
		l = sub.Replace(l)
		out = append(out, l)
	}
	for _, l := range out {
		if m := leftover.FindString(strings.ReplaceAll(l, "<KEY>", "")); m != "" {
			return nil, fmt.Errorf("deviceaaa: %s: placeholder %s left over", name, m)
		}
	}
	for _, p := range []struct{ ph, val string }{
		{"<SOURCE_INTERFACE>", v.SourceInterface}, {"<SOURCE_ADDRESS>", v.SourceAddress}, {"<MGMT_VRF>", v.MgmtVRF},
		{"<BREAKGLASS_USER>", v.BreakGlass}, {"<SERVER_NAME>", v.ServerName}, {"<CERT_ID>", v.CertID},
	} {
		if p.val == "" && strings.Contains(string(body), p.ph) && usedInCommand(string(body), p.ph) {
			return nil, fmt.Errorf("deviceaaa: %s needs %s", name, p.ph)
		}
	}
	for i, l := range out {
		out[i] = strings.ReplaceAll(l, "<KEY>", key)
	}
	return out, nil
}

// usedInCommand reports whether a command line, not just a comment, holds the placeholder.
func usedInCommand(body, ph string) bool {
	for _, l := range strings.Split(body, "\n") {
		if t := strings.TrimSpace(l); !strings.HasPrefix(t, "!") && !strings.HasPrefix(t, "#") && strings.Contains(l, ph) {
			return true
		}
	}
	return false
}

// repoRoot is the repository root, found from this file's place in it.
func repoRoot() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..")
}
