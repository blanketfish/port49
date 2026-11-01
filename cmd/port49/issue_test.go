package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/oidcclient"
	"github.com/blanketfish/port49/internal/testpki"
)

// A browser is launched only where one can be seen (decision 43 ruling 5).
func TestBrowserCommand(t *testing.T) {
	for _, c := range []struct {
		goos string
		env  map[string]string
		want string
	}{
		{"linux", map[string]string{"DISPLAY": ":0"}, "xdg-open U"},
		{"linux", map[string]string{"WAYLAND_DISPLAY": "wayland-0"}, "xdg-open U"},
		{"linux", map[string]string{"SSH_CONNECTION": "10.0.0.1 22 10.0.0.2 22"}, ""},
		{"linux", nil, ""},
		{"darwin", nil, "open U"},
		{"darwin", map[string]string{"SSH_TTY": "/dev/ttys001"}, ""},
		{"linux", map[string]string{"BROWSER": "firefox"}, "firefox U"},
		{"darwin", map[string]string{"BROWSER": "firefox", "SSH_TTY": "/dev/ttys001"}, "firefox U"},
	} {
		got := strings.Join(browserCommand(c.goos, func(k string) string { return c.env[k] }, "U"), " ")
		if got != c.want {
			t.Errorf("%s %v: %q, want %q", c.goos, c.env, got, c.want)
		}
	}
}

func TestPickProvider(t *testing.T) {
	one := api.Config{Methods: []string{"x509", "oidc"}, OIDC: []api.OIDCProvider{{Issuer: "https://a"}}}
	two := api.Config{Methods: []string{"oidc"}, OIDC: []api.OIDCProvider{{Issuer: "https://a"}, {Issuer: "https://b"}}}
	if p, err := pickProvider(one, ""); err != nil || p.Issuer != "https://a" {
		t.Fatalf("one: %v %v", p, err)
	}
	if p, err := pickProvider(two, "https://b"); err != nil || p.Issuer != "https://b" {
		t.Fatalf("named: %v %v", p, err)
	}
	for name, c := range map[string]struct {
		conf   api.Config
		issuer string
		want   string
	}{
		"none listed":  {api.Config{Methods: []string{"x509"}}, "", "takes no OIDC login"},
		"two unnamed":  {two, "", "name one with --issuer or oidc_issuer"},
		"not listed":   {two, "https://c", "does not list https://c"},
		"by its slash": {one, "https://a/", "does not list"},
	} {
		if _, err := pickProvider(c.conf, c.issuer); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// A skew over 5 minutes is said, never refused (ruling 6).
func TestASkewedClockIsWarnedNotRefused(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	var b bytes.Buffer
	warnSkew(&b, "port49 login", oidcclient.Tokens{ID: oidc.IDToken{IssuedAt: at}, Received: at.Add(2 * time.Minute)})
	if b.Len() != 0 {
		t.Fatalf("2m: %q", b.String())
	}
	warnSkew(&b, "port49 login", oidcclient.Tokens{ID: oidc.IDToken{IssuedAt: at}, Received: at.Add(-7 * time.Minute)})
	if !strings.Contains(b.String(), "this host's clock is 7m0s behind your identity provider's") {
		t.Fatalf("%q", b.String())
	}
}

// --cert or --key beside --oidc is a usage error, and so are the OIDC flags
// without it (ruling 19).
func TestTheLoginFlagsAreOneMethodsOrTheOthers(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--oidc", "--cert", "c.pem"}, "--cert and --key are a certificate login's"},
		{[]string{"--sign-in"}, "--sign-in is --oidc's"},
		{[]string{"--issuer", "https://a"}, "--issuer is --oidc's"},
	} {
		// An empty config file of its own: the test's default path may hold
		// another test's, and a missing --config is its own refusal.
		cfg := filepath.Join(privateDir(t), "config.yaml")
		if err := os.WriteFile(cfg, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		args := append(append([]string{"login"}, c.args...), "--broker", configBroker, "--broker-ca", "ca.pem",
			"--config", cfg)
		if code := run(args, &out, &errb); code != 2 || !strings.Contains(errb.String(), c.want) {
			t.Errorf("%v: code %d %q", c.args, code, errb.String())
		}
	}
}

// A held certificate is one port49 issued: missing files are ErrNotExist,
// and a certificate an organization's CA issued is not one.
func TestHeldCertificateReadsOnlyWhatTheBrokerIssued(t *testing.T) {
	dir := privateDir(t)
	if _, _, err := heldCertificate(filepath.Join(dir, "x.pem"), filepath.Join(dir, "x.key")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("no files: %v", err)
	}
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := heldCertificate(filepath.Join(dir, testpki.LabClientCert), filepath.Join(dir, testpki.LabClientKey)); err == nil ||
		!strings.Contains(err.Error(), "not a certificate port49 issued") {
		t.Fatalf("the lab's certificate: %v", err)
	}
}

// An agent that cannot make itself non-dumpable says so and runs on: the
// key is a file this user reads already (ruling 21).
func TestAnAgentThatCannotHardenRunsOn(t *testing.T) {
	saved := hardenAgent
	hardenAgent = func() error { return errors.New("prctl: operation not permitted") }
	t.Cleanup(func() { hardenAgent = saved })
	var out, errb bytes.Buffer
	if code := run([]string{"agent", "--broker-ca", "ca.pem", "--config", filepath.Join(t.TempDir(), "none.yaml")},
		&out, &errb); code != 2 || !strings.Contains(errb.String(), "could not make the agent non-dumpable") ||
		!strings.Contains(errb.String(), "it runs on") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

// A signal at the paste prompt restores the terminal before the process
// exits as the signal would: SIGUSR1 stands in for SIGINT, since SIGINT sent
// to the test binary would end it. (The real terminal's echo is untested: it
// needs a pty.)
func TestASignalAtThePastePromptRestoresTheTerminalFirst(t *testing.T) {
	var order []string
	exited := make(chan int, 1)
	release := make(chan struct{})
	got := make(chan struct{})
	go func() {
		_, _ = guardedPaste(func() (string, error) { close(got); <-release; return "", nil },
			func() { order = append(order, "restore") },
			func(code int) { order = append(order, "exit"); exited <- code },
			syscall.SIGUSR1)
	}()
	<-got
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-exited:
		if code != 128+int(syscall.SIGUSR1) || strings.Join(order, ",") != "restore,exit" {
			t.Fatalf("exit %d after %v", code, order)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the signal was not caught")
	}
	close(release)
}

// A paste that returns first leaves no handler behind and restores nothing.
func TestAPasteThatReturnsRestoresNothing(t *testing.T) {
	restored := false
	s, err := guardedPaste(func() (string, error) { return "https://x/cb", nil }, func() { restored = true },
		func(int) { t.Error("exited") }, syscall.SIGUSR2)
	if err != nil || s != "https://x/cb" || restored {
		t.Fatalf("%q %v restored %v", s, err, restored)
	}
}
