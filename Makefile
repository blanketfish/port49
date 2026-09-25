.PHONY: test lab-unit vet fuzz lab build evidence

build:
	go build -o bin/port49d ./cmd/port49d
	go build -o bin/port49 ./cmd/port49

test: lab-unit
	go test ./... -count=1

# The lab package's pure tests — the classifiers and row builders that read a
# device's output into a verdict, and the committed notes they must still
# read the same — live behind the `lab` tag with the harness they serve, so
# `go test ./...` never builds them. This runs each Test in a *_unit_test.go
# file, by anchored name, and nothing that brings a device up.
LAB_UNIT_TESTS = $(shell grep -ho '^func Test[A-Za-z0-9_]*' tests/lab/*_unit_test.go | sed 's/^func //' | paste -sd'|' -)

lab-unit:
	go test -tags lab ./tests/lab/ -run '^($(LAB_UNIT_TESTS))$$' -count=1

vet:
# gofmt lists every unformatted file and fails if there is one. No tee to
# /dev/stderr: that reopens stderr with O_TRUNC, which empties a log that
# `make test && make vet > log 2>&1` is writing.
	gofmt -l . | (! grep .)
	go vet ./...

# Short fuzz pass for every FuzzXxx in the packages that parse bytes off an
# unauthenticated connection; CI-sized. keyring is here because Resolve runs
# before any admission decision has been made: it is the first code a packet
# from an unknown source reaches.
FUZZ_PACKAGES ?= ./internal/tacacs/wire ./internal/keyring

fuzz:
	@set -e; \
	for p in $(FUZZ_PACKAGES); do \
	  for f in $$(go test -list 'Fuzz.*' $$p | grep '^Fuzz'); do \
	    echo "=== $$p $$f ==="; \
	    go test $$p -run '^$$' -fuzz "^$$f$$" -fuzztime 20s || exit 1; \
	  done; \
	done

# tests/lab/captures is git-ignored: a capture holds the lab tokens and the
# breakglass password, readable by anyone with the key this repository
# publishes. This rewrites each one into tests/lab/evidence with the credential
# bytes overwritten and everything else byte-identical, which is what the
# results notes point at and what gets committed.
#
# `make lab` runs this for itself at the end of a run, so a note never cites
# evidence that does not exist. Run it by hand after editing the redactor, or to
# regenerate the evidence from captures already on disk.
evidence:
	go run ./tests/lab/cmd/redact-pcap

# Requires containerlab and device images; see tests/lab/README.md.
#
# One `go test` per platform, because only one can be up at a time: they share
# the management subnet, the bridge address, and port 49 on the host. Within an
# invocation the topology is deployed once and every register test measures
# against it.
#
# 120m, not 30m: these are VM images that take minutes to boot, the harness
# waits up to six for each, and L5 alone holds a session open for 150 seconds.
#
# Override the set with either spelling:
#   PORT49_LAB_PLATFORMS=eos,vsrx make lab
#   make lab LAB_PLATFORMS="eos vsrx"
# `iosxe` is last for the reason `nxos` used to be: it is the platform here
# whose boot has never been measured on this host, so it sits behind the four
# that are known to work and a `make lab` with no selector gets through them
# first.
LAB_PLATFORMS ?= eos vjunos vsrx nxos iosxe

# A platform that does not measure stops the loop, and the `if` is how. `set -e`
# alone was not enough, and the reason is not the shell: it fires on a non-zero
# exit, and a platform can fail to measure while `go test` exits 0. Naming a
# platform whose image is absent used to skip every test and report success, so
# a three-platform run walked straight past it; so did a typo in a selector,
# which matched nothing and ran nothing. The harness now treats both as errors
# (see platformSelection in tests/lab/harness_test.go) and the loop says which
# platform stopped it rather than leaving that to `Error 1`.
lab:
	@set -e; \
	for p in $$(echo "$${PORT49_LAB_PLATFORMS:-$(LAB_PLATFORMS)}" | tr ',' ' '); do \
	  echo "=== lab platform: $$p ==="; \
	  if ! PORT49_LAB_PLATFORMS=$$p go test -tags lab ./tests/lab/... -count=1 -v -timeout 120m; then \
	    echo "=== lab platform $$p FAILED; the platforms after it were not run ==="; \
	    exit 1; \
	  fi; \
	done
