.PHONY: test test-race test-hw lab-unit vet fuzz lab lab-directory lab-l50 lab-oidc lab-oidc-l55 lab-oidc-agent lab-workload lab-oxidized lab-ssh build build-client check-static evidence image compose-smoke

# The static build (plan 9c, ruling 22): CGO_ENABLED=0 and no tag, whatever the
# environment says, so these are the four static binaries the image carries.
STATIC_CMDS = port49d port49 port49-inventory port49-broker

build:
	set -e; for c in $(STATIC_CMDS); do CGO_ENABLED=0 go build -o bin/$$c ./cmd/$$c; done

# The client build: the PKCS#11 backend through purego, which links the
# system's dynamic loader. Written beside, never over, bin/port49.
build-client:
	CGO_ENABLED=0 go build -tags hwkey_dlopen -o bin/port49-client ./cmd/port49

# The static build (the image's, decision 45 ruling 22) must stay static: a
# purego import outside a hwkey_dlopen file would make it need a loader that
# distroless/static does not have.
#
# Every binary `build` makes is checked, not only cmd/port49: a leak through a
# shared package reaches whichever ones import it. It fails closed: a missing
# readelf is an error, and readelf's own status is read (a pipe would give
# grep's, which reads a missing readelf as "static").
check-static:
	@set -e; \
	command -v readelf >/dev/null || { echo "check-static needs readelf (binutils); without it nothing is checked"; exit 1; }; \
	mkdir -p bin/static; \
	for c in $(STATIC_CMDS); do \
	  CGO_ENABLED=0 go build -o bin/static/$$c ./cmd/$$c; \
	  out=$$(readelf -l bin/static/$$c); \
	  if printf '%s\n' "$$out" | grep -q 'program interpreter'; then \
	    echo "bin/static/$$c is dynamically linked; the image cannot run it"; exit 1; fi; \
	done

# The packages the hwkey tag adds tests to. internal/clientkey arrives in
# plan 9c's Task 5; until then a pattern for it would fail the run.
HW_PACKAGES = ./internal/hwkey/... $(if $(wildcard internal/clientkey),./internal/clientkey/...) ./internal/agent/... ./internal/workload/... ./cmd/port49/...

# Hardware-key tests against SoftHSM2, swtpm and libykcs11 (plan 9c; decision
# 42 ruling 13), built with CGO_ENABLED=0 and the client build's tag so
# purego runs as the client binary does. Needs softhsm2, swtpm, ykcs11 and a
# running pcscd; PORT49_TEST_HW_REQUIRED makes a missing one a failure, not a
# skip. No -run: the hwkey tag already selects the hardware tests, and a
# pattern would silently leave a new one out.
test-hw: check-static
	CGO_ENABLED=0 PORT49_TEST_HW_REQUIRED=1 go test -tags hwkey,hwkey_dlopen $(HW_PACKAGES) -count=1 -timeout 20m

# internal/port49d runs about 9.5 minutes under the full parallel suite, close
# to go test's 10-minute default, so the limit is set here rather than left to
# turn a slow machine into a timeout panic.
test: lab-unit
	go test ./... -count=1 -timeout 20m

# The race detector over the daemon's packages. On the memory store a split
# between a login's mark check and its write that never yields between the
# two is caught only here: without -race the race property has nothing to
# interleave (plan 7d, R1).
test-race:
	go test -race ./internal/... -count=1

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
	go vet -tags compose ./tests/compose/...
	go vet -tags hwkey_dlopen ./...
	go vet -tags hwkey,hwkey_dlopen $(HW_PACKAGES)

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

# The directory lab (plan 7g): OpenLDAP and Samba AD as containers, no devices, so
# no containerlab and no image beyond debian:bookworm-slim. Needs Docker with
# Compose v2.24.4+; see tests/lab/README.md, "Directories".
lab-directory:
	go test -tags lab ./tests/lab/ -run 'TestL42|TestL43' -count=1 -v -timeout 30m

# L50 (plan 8b): who can write a workload mapping's attribute, on Samba AD and
# the Windows Server DC. Needs Docker with Compose v2.24.4+, KVM, the cached
# evaluation ISO and PORT49_LAB_L50=1; see tests/lab/README.md, "Directories".
lab-l50:
	PORT49_LAB_L50=1 go test -tags lab ./tests/lab/ -run '^TestL50WorkloadAttributeWriters$$' -count=1 -v -timeout 240m

# The identity-provider lab (plan 7h): Keycloak as a container, no devices.
# Needs Docker with Compose v2.24.4+; see tests/lab/README.md, "Identity provider".
lab-oidc:
	go test -tags lab ./tests/lab/ -run 'TestL45|TestL46' -count=1 -v -timeout 30m

# L55 (plan 9b): Keycloak as port49's OIDC public client meets it. Needs
# Docker with Compose v2.24.4+; a few minutes. lab-oidc re-measures the closed
# L45 and L46; this runs L55 alone.
lab-oidc-l55:
	go test -tags lab ./tests/lab/ -run 'TestL55' -count=1 -v -timeout 30m

# L56 (plan 9b): port49-issued certificates end to end, bin/port49 against
# the compose stack's Keycloak, broker and vEOS. Needs the compose stack,
# containerlab, the EOS image and `make build`.
lab-oidc-agent:
	PORT49_LAB_PLATFORMS=eos go test -tags lab ./tests/lab/ -run 'TestL56' -count=1 -v -timeout 60m

# The workload CA lab (plan 8, L48): step-ca as a container and a local
# port49d, no devices. Needs Docker with Compose v2.24.4+ and `make build`;
# see tests/lab/README.md, "Workload CA and Oxidized".
lab-workload:
	go test -tags lab ./tests/lab/ -run 'TestL48' -count=1 -v -timeout 75m

# Oxidized end to end (plan 8, L49): the compose stack with one platform, as
# `make lab` runs one at a time. Needs containerlab, the platform's image and
# `make build`.
lab-oxidized:
	@set -e; \
	for p in $$(echo "$${PORT49_LAB_PLATFORMS:-$(LAB_PLATFORMS)}" | tr ',' ' '); do \
	  echo "=== lab-oxidized platform: $$p ==="; \
	  if ! PORT49_LAB_PLATFORMS=$$p go test -tags lab ./tests/lab/ -run 'TestL49' -count=1 -v -timeout 90m; then \
	    echo "=== lab-oxidized platform $$p FAILED; the platforms after it were not run ==="; \
	    exit 1; \
	  fi; \
	done

# L53 and L54 (plan 9a): port49 devices trust and port49 ssh against each
# platform, one at a time as `make lab` runs them. Each device is reloaded
# once, so this is its own target. PORT49_LAB_REMEASURE passes through from
# the caller's environment only; set it to re-measure closed entries (e.g.,
# `PORT49_LAB_REMEASURE=L53,L54 make lab-ssh`). Needs containerlab, the
# images and `make build`.
lab-ssh:
	@set -e; \
	for p in $$(echo "$${PORT49_LAB_PLATFORMS:-$(LAB_PLATFORMS)}" | tr ',' ' '); do \
	  echo "=== lab-ssh platform: $$p ==="; \
	  if ! PORT49_LAB_SSH=1 PORT49_LAB_REMEASURE=$${PORT49_LAB_REMEASURE} PORT49_LAB_PLATFORMS=$$p go test -tags lab ./tests/lab/ -run 'TestL53L54PortSSH' -count=1 -v -timeout 90m; then \
	    echo "=== lab-ssh platform $$p FAILED; the platforms after it were not run ==="; \
	    exit 1; \
	  fi; \
	done

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

# The container image (plan 7f, Task 1): one peer shape, never required.
image:
	docker build --target port49 -t port49:dev .

# The compose stack end to end: up, a device login, the stack recreated
# with its volumes kept, the session and the broker's state_dir kept. Needs
# Docker with Compose v2.24.4+; behind the `compose` tag so `go test ./...`
# never needs Docker.
compose-smoke:
	go test -tags compose ./tests/compose/ -count=1 -v -timeout 20m
