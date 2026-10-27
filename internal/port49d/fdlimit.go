package port49d

import (
	"fmt"
	"syscall"
)

// reserveFDs are the descriptors the global cap leaves for everything but
// TACACS+ connections when it is sized from the limit: the spool, the store's
// connections, the decision log, the admin socket and metrics, the policy and
// inventory reads. minReserveFDs is the least an explicit cap may leave.
const (
	reserveFDs    = 1024
	minReserveFDs = 256
	maxCap        = 1 << 20
)

// openFileLimit is RLIMIT_NOFILE's soft limit, which the Go runtime raises to
// the hard limit at start; 0 when it cannot be read.
func openFileLimit() uint64 {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 0
	}
	return uint64(rl.Cur)
}

// connectionCap is limits.max_connections resolved (decision 53 ruling 8).
// Unset, it is the limit less reserveFDs, or half the limit where that is
// less, and at most maxCap; set, it must leave minReserveFDs.
func connectionCap(set int, nofile uint64) (int, error) {
	if nofile == 0 {
		nofile = 4096 // unreadable: a cap a stock host sustains
	}
	if set != 0 {
		if uint64(set)+minReserveFDs > nofile {
			return 0, fmt.Errorf("limits.max_connections %d leaves fewer than %d of the open-file limit %d for "+
				"the spool, the store and the logs; lower it, or raise the limit (LimitNOFILE= under systemd)",
				set, minReserveFDs, nofile)
		}
		return set, nil
	}
	n := nofile / 2
	if nofile > 2*reserveFDs {
		n = nofile - reserveFDs
	}
	return int(min(n, maxCap)), nil
}

// capSource is where the start line says the cap came from. An open-file
// limit that could not be read is said so, with the default the cap was
// sized from, never as a limit of 0.
func capSource(set int, limit uint64) string {
	switch {
	case set != 0:
		return "limits.max_connections"
	case limit == 0:
		return "the open-file limit could not be read, so 4096 is taken, less what the spool, the store and the logs keep"
	}
	return fmt.Sprintf("the open-file limit %d, less what the spool, the store and the logs keep", limit)
}
