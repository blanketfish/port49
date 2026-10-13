package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/mfatouch"
	"github.com/rhwendt/port49/internal/workload"
)

// mintOutcome says how a mint ended, on stderr, and the exit code it is: 0
// for none, exitTemporary when a run again may succeed (the broker did not
// answer by the deadline, or the connection changed during a touch, which a
// run again proves afresh), otherwise 1.
func mintOutcome(stderr io.Writer, cmd, scope string, devices []string, resp api.MintResponse, err error) int {
	var te *workload.TemporaryError
	switch {
	case errors.As(err, &te) && scope != "":
		fmt.Fprintf(stderr, "%s: %s: the sweep of scope %s stopped after %d tokens minted; run again\n", cmd,
			safe(err.Error()), safe(scope), mintedCount(resp.Results))
		return exitTemporary
	case errors.As(err, &te):
		fmt.Fprintf(stderr, "%s: %s: %d of %d devices were not minted; run again\n", cmd, safe(err.Error()),
			len(te.Unminted), len(devices))
		return exitTemporary
	case errors.Is(err, mfatouch.ErrConnectionChanged):
		// The touch was made for a connection that is gone and nothing was
		// posted; the error's own text says to run it again.
		fmt.Fprintf(stderr, "%s: %s: %d tokens minted\n", cmd, safe(err.Error()), mintedCount(resp.Results))
		return exitTemporary
	case err != nil && scope != "":
		fmt.Fprintf(stderr, "%s: %s: the sweep of scope %s stopped after %d tokens minted\n", cmd, safe(err.Error()),
			safe(scope), mintedCount(resp.Results))
		return 1
	case err != nil:
		// A final answer, perhaps after earlier pages minted: those are
		// still written (pre-flight I-1).
		fmt.Fprintf(stderr, "%s: %s: %d of %d devices were not minted\n", cmd, safe(err.Error()),
			len(devices)-len(resp.Results), len(devices))
		return 1
	}
	return 0
}
