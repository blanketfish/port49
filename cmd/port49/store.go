package main

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

	"github.com/rhwendt/port49/internal/config"
)

// storeStatusWait is how long the command waits for the answer: the status's
// own bound (each store's reads run at once, about two call_timeouts, and
// call_timeout is at most config.MaxCallTimeout) and a margin for the answer.
var storeStatusWait = 2*config.MaxCallTimeout + 10*time.Second

// maxStatusBody bounds what the command reads of an answer.
const maxStatusBody = 64 << 10

// storeCmd is `port49 store` (plan 11a): status asks a process's metrics
// listener what each of its stores is.
func storeCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "status" {
		return storeStatusCmd(args[1:], stdout, stderr)
	}
	fmt.Fprint(stderr, usage)
	return 2
}

// storeStatusCmd is `port49 store status --metrics ADDR` (spec §12; decision
// 51 R21): it reads GET /store/status on the metrics listener of port49d or
// port49-broker. Exit 0 when every store answers, 3 when one does not (the
// answer is still printed), 1 when the listener does not answer or another
// status is running.
func storeStatusCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 store status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("metrics", "127.0.0.1:9049", "the metrics_listen address of port49d or port49-broker (host:port)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeStatusWait)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+*addr+"/store/status", nil)
	if err != nil {
		fmt.Fprintln(stderr, "port49 store status: --metrics must be host:port:", safeLine(err.Error()))
		return 2
	}
	resp, err := (&http.Client{}).Do(req)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) {
		fmt.Fprintf(stderr, "port49 store status: %s did not answer within %v (is the process wedged?)\n",
			safeLine(*addr), storeStatusWait)
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, "port49 store status:", safeLine(err.Error()))
		return 1
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxStatusBody))
	if err != nil {
		fmt.Fprintln(stderr, "port49 store status:", safeLine(err.Error()))
		return 1
	}
	text := strings.TrimRight(safeText(string(body)), "\n")
	switch resp.StatusCode {
	case http.StatusOK:
		fmt.Fprintln(stdout, text)
		return 0
	case http.StatusServiceUnavailable:
		fmt.Fprintln(stdout, text)
		return 3
	case http.StatusTooManyRequests:
		fmt.Fprintln(stderr, "port49 store status: a status is already running on", safeLine(*addr)+"; ask again when it has answered")
		return 1
	}
	fmt.Fprintf(stderr, "port49 store status: %s answered %d\n", safeLine(*addr), resp.StatusCode)
	return 1
}
