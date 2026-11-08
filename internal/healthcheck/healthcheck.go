// Package healthcheck is the `healthcheck` subcommand of port49d, port49-broker and port49-inventory:
// a GET of /healthz or /readyz on the process's own metrics_listen, for an image with no shell and no
// curl. It loads no config (only the metrics_listen key is read, so a fence or store fault cannot make
// the check lie), binds nothing and reads no key. Every path exits 0 or 1: Docker reserves 2.
package healthcheck

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/printsafe"
)

// Timeout bounds one probe. It must stay under every container runtime's own healthcheck timeout (compose's
// is 3s): when the two meet, the runtime kills the probe and the operator sees a timeout, not the line
// the probe prints. tests/ci holds compose to it.
const Timeout = 2 * time.Second

// lineLimit bounds each printed line.
const lineLimit = 300

// DialAddr is the address to dial for a listen address: a wildcard host (empty, 0.0.0.0 or ::) is
// loopback.
func DialAddr(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}

// MetricsListen is metrics_listen as the config file at cfgPath names it, def (the role's default)
// when the key is empty. A file that does not read or parse is an error: a missing config must not
// probe the default and pass.
func MetricsListen(cfgPath, def string) (string, error) {
	raw, err := config.ReadRegular(cfgPath, config.MaxConfigSize)
	if err != nil {
		return "", err
	}
	var c struct {
		MetricsListen string `yaml:"metrics_listen"`
	}
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return "", fmt.Errorf("%s: %w", cfgPath, err)
	}
	if c.MetricsListen == "" {
		return def, nil
	}
	return c.MetricsListen, nil
}

// Run GETs path on listen within Timeout. It returns 0 on a 200, else 1 after one line on out.
func Run(ctx context.Context, listen, path string, out io.Writer) int {
	addr, err := DialAddr(listen)
	if err != nil {
		return fail(out, "%v", err)
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+path, nil)
	if err != nil {
		return fail(out, "%v", err)
	}
	// The metrics port is this process's own: no proxy from the environment sits between the probe and it.
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return fail(out, "%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return 0
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	first, _, _ := strings.Cut(strings.TrimSpace(string(body)), "\n")
	if first = strings.TrimSpace(first); first != "" {
		return fail(out, "%s answered %d: %s", path, resp.StatusCode, first)
	}
	return fail(out, "%s answered %d", path, resp.StatusCode)
}

func fail(out io.Writer, format string, args ...any) int {
	fmt.Fprintln(out, printsafe.Line("healthcheck: "+fmt.Sprintf(format, args...), lineLimit))
	return 1
}

// Command is `<name> healthcheck [--ready] [--config FILE]`: /healthz (liveness) by default, /readyz
// with --ready. defCfg is the binary's own default config path and defListen its metrics_listen
// default. It parses its own flags so that a bad one exits 1, never 2.
func Command(name, defCfg, defListen string, args []string, out io.Writer) int {
	fs := flag.NewFlagSet(name+" healthcheck", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfgPath := fs.String("config", defCfg, "path to "+name+"'s yaml")
	ready := fs.Bool("ready", false, "probe /readyz (readiness) instead of /healthz (liveness)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(out, "usage: %s healthcheck [--ready] [--config FILE]\n", name)
			return 0
		}
		return fail(out, "%v (usage: %s healthcheck [--ready] [--config FILE])", err, name)
	}
	if fs.NArg() != 0 {
		return fail(out, "unexpected argument %q (usage: %s healthcheck [--ready] [--config FILE])", fs.Arg(0), name)
	}
	listen, err := MetricsListen(*cfgPath, defListen)
	if err != nil {
		return fail(out, "%v", err)
	}
	path := "/healthz"
	if *ready {
		path = "/readyz"
	}
	return Run(context.Background(), listen, path, out)
}
