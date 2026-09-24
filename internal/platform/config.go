package platform

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
)

// LocalAccount is a device-local account a configuration declares, and the
// line that declares it.
type LocalAccount struct {
	Name string
	Line int
}

// ConfigFinding is a configuration line one of the adapter's checks names.
type ConfigFinding struct {
	Line int
	Text string
	Says string
}

// ReadConfig reads a device's configuration text, as `show running-config`
// prints it, against the adapter: every local account its LocalAccounts
// patterns name, every line a ConfigChecks entry matches, and an error where
// the text could not be read to the end. It is a lab and CI instrument: port49
// never logs into a device (spec §8, "Verification").
func (d Dialect) ReadConfig(config []byte) ([]LocalAccount, []ConfigFinding, error) {
	var accounts []LocalAccount
	var findings []ConfigFinding
	var accountRes, checkRes []*regexp.Regexp
	// Validate compiled every pattern; one that does not compile here is
	// skipped rather than trusted to panic.
	for _, p := range d.LocalAccounts {
		if re, err := regexp.Compile(p); err == nil && re.NumSubexp() == 1 {
			accountRes = append(accountRes, re)
		}
	}
	checks := make(map[*regexp.Regexp]string)
	for _, c := range d.ConfigChecks {
		if re, err := regexp.Compile(c.Match); err == nil {
			checkRes, checks[re] = append(checkRes, re), c.Says
		}
	}
	sc := bufio.NewScanner(bytes.NewReader(config))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		for _, re := range accountRes {
			if m := re.FindStringSubmatch(line); m != nil {
				accounts = append(accounts, LocalAccount{Name: m[1], Line: n})
			}
		}
		for _, re := range checkRes {
			if re.MatchString(line) {
				findings = append(findings, ConfigFinding{Line: n, Text: line, Says: checks[re]})
			}
		}
	}
	// A read that stopped short is not a clean configuration: whatever
	// followed the line it stopped at was never checked.
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("the configuration was not read to the end: %w", err)
	}
	return accounts, findings, nil
}
