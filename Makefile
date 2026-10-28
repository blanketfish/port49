.PHONY: qual qual-vet qual-update qual-fleet qualified-platforms test test-rest race-rest test-shard race-shard test-root test-python test-race test-hw lab-unit lab-l62-up vet fuzz lab lab-regress lab-qualify lab-directory lab-regions lab-l50 lab-l67 lab-l80 lab-l84 lab-l84-systemd lab-l67-windows lab-oidc lab-oidc-l55 lab-mfa-idp lab-oidc-agent lab-workload lab-oxidized lab-ssh lab-ansible lab-k8s build build-client l86-build check-static check-darwin evidence image image-check compose-smoke leaks packages packages-check release-packages helm-test kind-smoke kind-smoke-red systemd-smoke

# The static build (plan 9c, ruling 22): CGO_ENABLED=0 and no tag, whatever the
# environment says, so these are the four static binaries the image carries.
STATIC_CMDS = port49d port49 port49-inventory port49-broker

build:
	set -e; for c in $(STATIC_CMDS); do CGO_ENABLED=0 go build -o bin/$$c ./cmd/$$c; done

# The client build: the PKCS#11 backend through purego, which links the
# system's dynamic loader. Written beside, never over, bin/port49.
build-client:
	CGO_ENABLED=0 go build -tags hwkey_dlopen -o bin/port49-client ./cmd/port49

# L86's binaries, at the fixed paths tests/lab/L86-runbook.md runs: the client and the L86 cells
# as one compiled test binary, so what Ryan runs is this tree's. Nothing here touches a token.
l86-build:
	mkdir -p bin/l86
	CGO_ENABLED=0 go build -tags hwkey_dlopen -o bin/l86/port49 ./cmd/port49
	CGO_ENABLED=0 go test -tags hwkey_dlopen -c -o bin/l86/l60.test ./tests/lab/l60

# The Secure Enclave backend and the L63 spike, built and vetted for macOS
# without a Mac (decision 45 ruling 6): the client build of port49 and the
# spike for arm64 and amd64, CGO_ENABLED=0, then go vet over every package
# for darwin in both builds. Nothing here runs them; a Mac user does.
DARWIN_ARCHES = arm64 amd64

check-darwin:
	@set -e; for a in $(DARWIN_ARCHES); do \
	  echo "darwin/$$a"; \
	  CGO_ENABLED=0 GOOS=darwin GOARCH=$$a go build -tags hwkey_dlopen -o /dev/null ./cmd/port49; \
	  CGO_ENABLED=0 GOOS=darwin GOARCH=$$a go build -o /dev/null ./tests/spike/secureenclave; \
	  CGO_ENABLED=0 GOOS=darwin GOARCH=$$a go vet ./...; \
	  CGO_ENABLED=0 GOOS=darwin GOARCH=$$a go vet -tags hwkey_dlopen ./...; \
	done

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

# The packages the hwkey tag adds tests to.
HW_PACKAGES = ./internal/hwkey/... ./internal/clientkey/... ./internal/agent/... ./internal/workload/... ./cmd/port49/...

# Hardware-key tests against SoftHSM2, swtpm and libykcs11 (plan 9c; decision
# 42 ruling 13), built with CGO_ENABLED=0 and the client build's tag so
# purego runs as the client binary does. Needs softhsm2, swtpm, ykcs11 and a
# running pcscd; PORT49_TEST_HW_REQUIRED makes a missing one a failure, not a
# skip. No -run: the hwkey tag already selects the hardware tests, and a
# pattern would silently leave a new one out.
test-hw: check-static
	CGO_ENABLED=0 PORT49_TEST_HW_REQUIRED=1 go test -tags hwkey,hwkey_dlopen $(HW_PACKAGES) -count=1 -timeout 20m

# internal/port49d took about 943 s under the full parallel suite (12a), against
# a 20-minute limit, so the limit is set here rather than left to turn a slow
# machine into a timeout panic.
test: lab-unit test-python
	go test ./... -count=1 -timeout 30m

# CI runs the suite in three kinds of job (.github/workflows/test.yml):
#   test-rest   everything but internal/port49d, plus the ACL and busybox tests
#               that must not skip;
#   test-shard  one third of internal/port49d, SHARD=i/n. tests/ci/cmd/testshard
#               builds the regex from `go test -list`, and fails when it lists
#               nothing or the shard is empty; a separate job checks that the
#               shards together hold every test;
#   test-root   the tests that skip unless run as root, which must pass, not skip.
# A skip in a must-pass test fails: tests/ci/cmd/mustpass reads go test -json.
PORT49D_PKG = github.com/rhwendt/port49/internal/port49d
ACL_TEST = TestAnACLGrantingWriteIsRefused
# The tests that must pass, not skip, as a comma list: it is mustpass's -tests as it stands,
# and test-root turns it into the -run alternation below.
ROOT_TESTS = TestAKeyFileTheBrokerDidNotWriteIsRefused
# The secret filter's busybox engine skips where busybox is absent: CI installs it, and a skip fails.
FILTER_TEST = TestSecretFilterEngines/busybox
comma := ,
REST_PKGS = $$(go list -f '{{if ne .ImportPath "$(PORT49D_PKG)"}}{{.ImportPath}}{{end}}' ./...)
# RACE=-race runs a shard under the race detector (CI's race jobs, 4 shards).
RACE ?=

test-rest: lab-unit test-python
	go test $(REST_PKGS) -count=1 -timeout 30m
	go test -json ./internal/fence/ -run '^$(ACL_TEST)$$' -count=1 | go run ./tests/ci/cmd/mustpass -tests $(ACL_TEST)
	go test -json ./tests/qual/ -run '^TestSecretFilterEngines$$' -count=1 | go run ./tests/ci/cmd/mustpass -tests $(FILTER_TEST)

race-rest:
	go test -race $(REST_PKGS) -count=1 -timeout 30m

test-shard:
	@test -n "$(SHARD)" || { echo "usage: make test-shard SHARD=i/n"; exit 2; }
	@re=$$(go run ./tests/ci/cmd/testshard -pkg ./internal/port49d -shard $(SHARD)) || exit 1; \
	  go test $(RACE) ./internal/port49d/ -count=1 -timeout 30m -run "$$re"

race-shard:
	$(MAKE) test-shard RACE=-race SHARD=$(SHARD)

test-root:
	@test "$$(id -u)" = 0 || { echo "make test-root must run as root (sudo -E env \"PATH=\$$PATH\" make test-root)"; exit 1; }
	go test -json ./internal/port49d/ -run '^($(subst $(comma),|,$(ROOT_TESTS)))$$' -count=1 | go run ./tests/ci/cmd/mustpass -tests $(ROOT_TESTS)

# The Python library and the Ansible lookup (plan 9d), stdlib unittest. A
# missing python3 fails it: make test runs it (decision 46 ruling 14).
PYTHON ?= python3

test-python:
	@$(PYTHON) -c 'import sys; sys.exit(sys.version_info < (3, 10))' || { \
	  echo "make test needs python3 3.10 or later (decision 46 ruling 14)"; exit 1; }
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s clients/python/tests -v
	@if [ -d clients/ansible/ansible_collections/port49/client/tests/unit ]; then \
	  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=clients/python/src:clients/ansible $(PYTHON) -m unittest discover \
	    -s clients/ansible/ansible_collections/port49/client/tests/unit -v; fi

# The race detector over the daemon's packages. On the memory store a split
# between a login's mark check and its write that never yields between the
# two is caught only here: without -race the race property has nothing to
# interleave (plan 7d, R1).
test-race:
	go test -race -timeout 30m ./internal/... -count=1

# The lab package's pure tests — the classifiers and row builders that read a
# device's output into a verdict, and the committed notes they must still
# read the same — live behind the `lab` tag with the harness they serve, so
# `go test ./...` never builds them. This runs each Test in a *_unit_test.go
# file, by anchored name, and nothing that brings a device up.
LAB_UNIT_TESTS = $(shell grep -ho '^func Test[A-Za-z0-9_]*' tests/lab/*_unit_test.go | sed 's/^func //' | paste -sd'|' -)

L62_UNIT_TESTS = $(shell grep -ho '^func Test[A-Za-z0-9_]*' tests/lab/l62/*_unit_test.go | sed 's/^func //' | paste -sd'|' -)

lab-unit:
	go test -tags lab ./tests/lab/ -run '^($(LAB_UNIT_TESTS))$$' -count=1
	go test -tags lab ./tests/lab/l62/ -run '^($(L62_UNIT_TESTS))$$' -count=1

# The L62 session's stand-up (runbooks/L62-ser8.md, P0): the lab Keycloak and
# an issuing port49-broker as compose project port49labl62, held until Enter.
# State is kept in ~/.cache/port49-l62 and reused; PORT49_L62_FRESH=1 starts
# over. Needs Docker with Compose v2.24.4+. No device, no TPM.
lab-l62-up:
	PORT49_L62_UP=1 go test -tags lab ./tests/lab/l62/ -run '^TestL62Up$$' -count=1 -v -timeout 10h

# The mock tier (plan 11b): every profile against a real in-process port49d. No images,
# no captures, any runner. qual-update rewrites the goldens a port49 change moved, marked
# pending_lab until the next lab run.
qual:
	go test ./internal/devicemock/... ./tests/qual/... -count=1
	go test ./internal/port49d/ -run '^TestQual' -count=1 -timeout 20m

# Fleet mode (plan 11b): N mock devices from N loopback addresses against one port49d.
# Linux. Plan 12's load validation drives it at the §5 target rate.
qual-fleet:
	PORT49_QUAL_FLEET=1 go test ./internal/port49d/ -run '^TestQualFleet$$' -count=1 -v -timeout 30m

# docs/qualified-platforms.md, generated from the profiles, goldens and notes; a test fails
# while the committed page is stale.
qualified-platforms:
	go run ./tests/qual/cmd/qualified > docs/qualified-platforms.md

# Vet a firmware and generate its mock for review (tests/qual/README.md). Commits nothing.
qual-vet:
	@test -n "$(P)" || { echo "usage: make qual-vet P=<selector>"; exit 2; }
	bash tests/qual/vet.sh $(P)

qual-update:
	PORT49_QUAL_UPDATE=1 go test ./internal/port49d/ -run '^TestQual$$' -count=1 -timeout 20m

vet:
# gofmt lists every unformatted file and fails if there is one. No tee to
# /dev/stderr: that reopens stderr with O_TRUNC, which empties a log that
# `make test && make vet > log 2>&1` is writing.
	gofmt -l . | (! grep .)
	go vet ./...
	go vet -tags compose ./tests/compose/...
	go vet -tags hwkey_dlopen ./...
	go vet -tags hwkey,hwkey_dlopen $(HW_PACKAGES) ./tests/lab/l60/
	go vet -tags systemd,helm,kind,image,packages ./tests/...
	go vet -tags lab ./tests/lab/

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

# L74 and L75 (plan 11a): three simulated regions on this host; needs sudo -n,
# PORT49_LAB_ETCD_BIN (etcd v3.6.15) and the L67 directory containers' images.
lab-regions:
	go test -tags lab ./tests/lab/ -run '^TestRegions$$' -count=1 -timeout 120m -v

# The closed lab entries, rerun under the lab lock and diffed against their notes
# (plan 11b). Beehive only. LAB_REGRESS_ARGS passes -only=<ids> or -dry-run.
lab-regress: build
	go run ./tests/lab/cmd/lab-regress -manifest tests/lab/regress.yaml $(LAB_REGRESS_ARGS)

# L50 (plan 8b): who can write a workload mapping's attribute, on Samba AD and
# the Windows Server DC. Needs Docker with Compose v2.24.4+, KVM, the cached
# evaluation ISO and PORT49_LAB_L50=1; see tests/lab/README.md, "Directories".
lab-l50:
	PORT49_LAB_L50=1 go test -tags lab ./tests/lab/ -run '^TestL50WorkloadAttributeWriters$$' -count=1 -v -timeout 240m

# The conformance run a firmware is vetted by (plan 11b). One platform selector at a time.
# A re-vet of nxos106 re-measures L80 (closed), so PORT49_LAB_REMEASURE defaults to it there and nowhere else.
lab-qualify:
	@test -n "$(P)" || { echo "usage: make lab-qualify P=<selector, e.g. nxos106>"; exit 2; }
	PORT49_LAB_QUALIFY=1 PORT49_LAB_REMEASURE=$${PORT49_LAB_REMEASURE:-$(if $(filter nxos106,$(P)),L80)} PORT49_LAB_PLATFORMS=$(P) go test -tags lab ./tests/lab/ -run '^TestQualify$$' -count=1 -v -timeout 180m

# L80's re-measure (decision 50 ruling 20): nxos106 over per-request TLS at the default
# idle_timeout. The harness builds bin/port49d itself, in a private clone: ARM=baseline from
# the commit before the fix, ARM=fixed from HEAD. Commit earlier evidence first (the tree must
# be clean). CELLS=s1,idle31 runs a subset.
lab-l80:
	@case "$(ARM)" in baseline|fixed) ;; *) echo "usage: make lab-l80 ARM=baseline|fixed [CELLS=...]"; exit 2;; esac
	PORT49_L80_ARM=$(ARM) PORT49_L80_CELLS=$(CELLS) PORT49_LAB_PLATFORMS=nxos106 go test -tags lab ./tests/lab/ -run '^TestL80Remeasure$$' -count=1 -v -timeout 240m

# L84 (plan 12b, Task 15): host credential mechanisms against fence.ReadSecret. lab-l84 runs the Compose
# cells on the local images (nothing is pulled or built) and writes the note from the cells; with
# A_CELLS=<json from lab-l84-systemd> it merges the systemd cells. lab-l84-systemd runs cell (a) and its (c) in
# Task 9's container (needs `make packages` and the debian image) and writes the cells to CELLS_OUT.
lab-l84:
	PORT49_L84_NOTE=$(CURDIR)/tests/lab/results/L84-systemd-docker.md $(if $(A_CELLS),PORT49_L84_A_CELLS=$(A_CELLS)) go test -tags lab ./tests/lab/ -run '^TestL84$$' -count=1 -v -timeout 30m

lab-l84-systemd: packages
	@test -n "$(CELLS_OUT)" || { echo "usage: make lab-l84-systemd CELLS_OUT=/path/cells.json"; exit 2; }
	PORT49_L84_CELLS_OUT=$(CELLS_OUT) go test -tags systemd ./tests/systemd/ -run '^TestL84Credentials$$' -count=1 -v -timeout 30m

# L67 (plan 9e): a person's bind and the directory-password sign-in, on
# OpenLDAP and Samba AD as containers. Needs Docker with Compose v2.24.4+
# and `make build`; see tests/lab/README.md, "Directories". Cell (g)'s etcd half
# runs on the compose stack, so it also brings up the lab's arista_eos or
# juniper_vjunos-router (TestDirectoryEndToEnd's platforms), as that test does.
lab-l67:
	go test -tags lab ./tests/lab/ -run '^TestL67$$' -count=1 -v -timeout 45m

# L67 on the Windows Server DC (the L44 harness, on the SER8). Needs KVM, the
# cached evaluation ISO and PORT49_LAB_L67_WINDOWS=1.
lab-l67-windows:
	PORT49_LAB_L67_WINDOWS=1 go test -tags lab ./tests/lab/ -run '^TestL67Windows$$' -count=1 -v -timeout 240m

# The identity-provider lab (plan 7h): Keycloak as a container, no devices.
# Needs Docker with Compose v2.24.4+; see tests/lab/README.md, "Identity provider".
lab-oidc:
	go test -tags lab ./tests/lab/ -run 'TestL45|TestL46' -count=1 -v -timeout 30m

# L55 (plan 9b): Keycloak as port49's OIDC public client meets it. Needs
# Docker with Compose v2.24.4+; a few minutes. lab-oidc re-measures the closed
# L45 and L46; this runs L55 alone.
lab-oidc-l55:
	go test -tags lab ./tests/lab/ -run 'TestL55' -count=1 -v -timeout 30m

# L61 (plan 9c): Keycloak's amr and acr for idp_mfa, a password-and-OTP realm
# flow against the same compose Keycloak. Needs Docker with Compose v2.24.4+.
lab-mfa-idp:
	go test -tags lab ./tests/lab/ -run 'TestL61' -count=1 -v -timeout 30m

# L56 (plan 9b): port49-issued certificates end to end, bin/port49 against
# the compose stack's Keycloak, broker and vEOS. Needs the compose stack,
# containerlab, the EOS image and `make build`.
lab-oidc-agent:
	PORT49_LAB_PLATFORMS=eos go test -tags lab ./tests/lab/ -run 'TestL56' -count=1 -v -timeout 60m

# L69 (plan 10): a Kubernetes cluster's service account tokens, on two kind
# clusters and a local port49d, no devices. Needs Docker, kind v0.29.0 on PATH
# (go install sigs.k8s.io/kind@v0.29.0), kubectl and `make build`; see
# tests/lab/README.md, "Kubernetes (L69)".
lab-k8s:
	PORT49_LAB_K8S=1 go test -tags lab ./tests/lab/ -run '^TestL69$$' -count=1 -v -timeout 60m

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

# L64 and L65 (plan 9d): `port49 ssh` under OpenSSH's accept-new and the Python
# client against each platform, one at a time as `make lab` runs them. Each
# device is reloaded once, so this is its own target. It installs
# ./clients/python[netmiko] into /home/rwendt/lab-venv first. L53 (the host-key
# scan) is closed and runs only as `PORT49_LAB_REMEASURE=L53 go test -tags lab
# ./tests/lab/ -run TestL53HostKeyScan` with PORT49_LAB_SSH=1.
# PORT49_LAB_REMEASURE passes through from the caller's environment only; set
# it to re-measure closed entries (e.g., `PORT49_LAB_REMEASURE=L64 make
# lab-ssh`). Needs containerlab, the images and `make build`.
lab-ssh:
	@set -e; \
	for p in $$(echo "$${PORT49_LAB_PLATFORMS:-$(LAB_PLATFORMS)}" | tr ',' ' '); do \
	  echo "=== lab-ssh platform: $$p ==="; \
	  if ! PORT49_LAB_SSH=1 PORT49_LAB_REMEASURE=$${PORT49_LAB_REMEASURE} PORT49_LAB_PLATFORMS=$$p go test -tags lab ./tests/lab/ -run 'TestL64L65' -count=1 -v -timeout 180m; then \
	    echo "=== lab-ssh platform $$p FAILED; the platforms after it were not run ==="; \
	    exit 1; \
	  fi; \
	done

# L66 (plan 9d): the Ansible lookup `port49.client.token` over network_cli and
# the host keys of Ansible's connection plugins, one platform at a time. It
# installs nothing: the venv needs ansible-pylibssh and ./clients/python, and
# tests/lab/l66/.collections the platform collections (the harness names the
# command when one is missing). Needs libnss-wrapper (libssh takes its home
# from the passwd entry; every play runs under nss_wrapper with the private one),
# docker with alpine:3.22 pulled, containerlab, the images and `make build`.
lab-ansible:
	@set -e; \
	for p in $$(echo "$${PORT49_LAB_PLATFORMS:-$(LAB_PLATFORMS)}" | tr ',' ' '); do \
	  echo "=== lab-ansible platform: $$p ==="; \
	  if ! PORT49_LAB_ANSIBLE=1 PORT49_LAB_PLATFORMS=$$p go test -tags lab ./tests/lab/ -run 'TestL66' -count=1 -v -timeout 90m; then \
	    echo "=== lab-ansible platform $$p FAILED; the platforms after it were not run ==="; \
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

# The image's directory and binary modes (plan 12b, Task 5): builds, then reads the
# exported filesystem. Behind the image tag so `go test ./...` never needs Docker.
image-check: image
	go test -tags image ./tests/image/ -count=1 -v

# The compose stack end to end: up, a device login, the stack recreated
# with its volumes kept, the session and the broker's state_dir kept. Needs
# Docker with Compose v2.24.4+; behind the `compose` tag so `go test ./...`
# never needs Docker.
compose-smoke:
	go test -tags compose ./tests/compose/ -count=1 -v -timeout 20m

# Secret scanning (.gitleaks.toml). The pinned release is downloaded into bin/ and verified by
# sha256. CI runs `make leaks`, so this is the single pin: bump the version and the checksum
# together. --redact on every run: a finding's value is never printed. Never re-run a finding
# without it. --ignore-gitleaks-allow: no inline `gitleaks:allow` bypass; entries go in
# .gitleaks.toml or .gitleaksignore.
GITLEAKS_VERSION ?= 8.30.1
GITLEAKS_SHA256_LINUX_X64 = 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
GITLEAKS_FLAGS = --redact --no-banner --ignore-gitleaks-allow --config .gitleaks.toml

# The binary is named for its version, so a bump fetches the new one.
bin/gitleaks-$(GITLEAKS_VERSION):
	@test "$$(uname -sm)" = "Linux x86_64" || { echo "install gitleaks $(GITLEAKS_VERSION) yourself and put it at bin/gitleaks-$(GITLEAKS_VERSION)"; exit 2; }
	mkdir -p bin
	curl -fsSL -o bin/gitleaks.tar.gz https://github.com/gitleaks/gitleaks/releases/download/v$(GITLEAKS_VERSION)/gitleaks_$(GITLEAKS_VERSION)_linux_x64.tar.gz
	echo "$(GITLEAKS_SHA256_LINUX_X64)  bin/gitleaks.tar.gz" | sha256sum -c -
	tar -xzf bin/gitleaks.tar.gz -C bin gitleaks
	mv bin/gitleaks bin/gitleaks-$(GITLEAKS_VERSION)
	rm bin/gitleaks.tar.gz

# Release packages (plan 12b, Task 8). GoReleaser is pinned by sha256 like gitleaks. UNVERIFIED:
# this target and the pinned digest have not been run; the first `make packages` is the check.
# `make packages` builds dist/ locally and publishes and signs nothing (--snapshot
# --skip=publish,sign): signing belongs to the release workflow.
# `make packages-check` then runs tests/packages, which fails, never skips, when dist/ is empty.
GORELEASER_VERSION ?= 2.19.0
GORELEASER_SHA256_LINUX_X64 = ebc3194ad1d1b1787614405285a0039665cd4c5bd3305215a1b201600f90630b

bin/goreleaser-$(GORELEASER_VERSION):
	@test "$$(uname -sm)" = "Linux x86_64" || { echo "install goreleaser $(GORELEASER_VERSION) yourself and put it at bin/goreleaser-$(GORELEASER_VERSION)"; exit 2; }
	mkdir -p bin
	curl -fsSL -o bin/goreleaser.tar.gz https://github.com/goreleaser/goreleaser/releases/download/v$(GORELEASER_VERSION)/goreleaser_Linux_x86_64.tar.gz
	echo "$(GORELEASER_SHA256_LINUX_X64)  bin/goreleaser.tar.gz" | sha256sum -c -
	tar -xzf bin/goreleaser.tar.gz -C bin goreleaser
	mv bin/goreleaser bin/goreleaser-$(GORELEASER_VERSION)
	rm bin/goreleaser.tar.gz

packages: bin/goreleaser-$(GORELEASER_VERSION)
	bin/goreleaser-$(GORELEASER_VERSION) release --snapshot --clean --skip=publish,sign

# The release workflow's step: the same pinned binary, publishing (GITHUB_TOKEN in its environment).
# Never run locally; make packages is the local build.
release-packages: bin/goreleaser-$(GORELEASER_VERSION)
	bin/goreleaser-$(GORELEASER_VERSION) release --clean

# The Helm chart's render checks (plan 12b, Task 10). Helm is pinned by sha256 (the digest is the
# one get.helm.sh's .sha256sum and the GitHub release both give). UNVERIFIED: this target has not
# been run; the first `make helm-test` is the check. tests/helm's helm-tagged files fail, never
# skip, when bin/helm-$(HELM_VERSION) is absent; `make test` never builds them.
HELM_VERSION ?= 3.22.0
HELM_SHA256_LINUX_AMD64 = 1e4ab49e429626cf6c6958d914248b78c9730803c2751b87627e171dc800e7bb

bin/helm-$(HELM_VERSION):
	@test "$$(uname -sm)" = "Linux x86_64" || { echo "install helm $(HELM_VERSION) yourself and put it at bin/helm-$(HELM_VERSION)"; exit 2; }
	mkdir -p bin
	curl -fsSL -o bin/helm.tar.gz https://get.helm.sh/helm-v$(HELM_VERSION)-linux-amd64.tar.gz
	echo "$(HELM_SHA256_LINUX_AMD64)  bin/helm.tar.gz" | sha256sum -c -
	tar -xzf bin/helm.tar.gz -C bin --strip-components=1 linux-amd64/helm
	mv bin/helm bin/helm-$(HELM_VERSION)
	rm bin/helm.tar.gz

helm-test: bin/helm-$(HELM_VERSION)
	HELM_BIN=$(CURDIR)/bin/helm-$(HELM_VERSION) go test -tags helm -count=1 ./tests/helm/

# The Kubernetes shape end to end (plan 12b, Task 11): the chart on a kind cluster. kind and kubectl are
# pinned by sha256 like helm. UNVERIFIED: none of these targets has run; the first `make kind-smoke` is
# the check. Behind the `kind` tag so `go test ./...` never needs Docker or a cluster, and it fails,
# never skips, without the pinned tools. The post-renderer for the fsGroup cell's red run is built
# here, test-only, and is not part of the chart.
KIND_VERSION ?= 0.29.0
KIND_SHA256_LINUX_AMD64 = c72eda46430f065fb45c5f70e7c957cc9209402ef309294821978677c8fb3284
KUBECTL_VERSION ?= 1.33.1
KUBECTL_SHA256_LINUX_AMD64 = 5de4e9f2266738fd112b721265a0c1cd7f4e5208b670f811861f699474a100a3

bin/kind-v$(KIND_VERSION):
	@test "$$(uname -sm)" = "Linux x86_64" || { echo "install kind v$(KIND_VERSION) yourself and put it at bin/kind-v$(KIND_VERSION)"; exit 2; }
	mkdir -p bin
	curl -fsSL -o bin/kind.dl https://github.com/kubernetes-sigs/kind/releases/download/v$(KIND_VERSION)/kind-linux-amd64
	echo "$(KIND_SHA256_LINUX_AMD64)  bin/kind.dl" | sha256sum -c -
	chmod 0755 bin/kind.dl
	mv bin/kind.dl bin/kind-v$(KIND_VERSION)

bin/kubectl-$(KUBECTL_VERSION):
	@test "$$(uname -sm)" = "Linux x86_64" || { echo "install kubectl v$(KUBECTL_VERSION) yourself and put it at bin/kubectl-$(KUBECTL_VERSION)"; exit 2; }
	mkdir -p bin
	curl -fsSL -o bin/kubectl.dl https://dl.k8s.io/release/v$(KUBECTL_VERSION)/bin/linux/amd64/kubectl
	echo "$(KUBECTL_SHA256_LINUX_AMD64)  bin/kubectl.dl" | sha256sum -c -
	chmod 0755 bin/kubectl.dl
	mv bin/kubectl.dl bin/kubectl-$(KUBECTL_VERSION)

# Whatever the result, the cluster is deleted afterwards (the test's own guard covers a signal and the
# deadline; this covers a make killed between them). To clean up by hand after any aborted run:
# `bin/kind-v$(KIND_VERSION) delete cluster --name port49smoke`, then `kind get clusters` is empty.
kind-smoke: image build bin/kind-v$(KIND_VERSION) bin/kubectl-$(KUBECTL_VERSION) bin/helm-$(HELM_VERSION)
	docker build --target setup -t port49-setup:dev .
	go build -o bin/oldroot ./tests/kind/cmd/oldroot
	rc=0; KIND_BIN=$(CURDIR)/bin/kind-v$(KIND_VERSION) KUBECTL_BIN=$(CURDIR)/bin/kubectl-$(KUBECTL_VERSION) \
	  HELM_BIN=$(CURDIR)/bin/helm-$(HELM_VERSION) OLDROOT_BIN=$(CURDIR)/bin/oldroot \
	  go test -tags kind ./tests/kind/ -count=1 -v -timeout 40m || rc=$$?; \
	  $(CURDIR)/bin/kind-v$(KIND_VERSION) delete cluster --name port49smoke; exit $$rc

packages-check:
	go test -tags packages ./tests/packages/ -count=1 -v

# The history scan is of the checked-out branch only (--log-opts=HEAD), which is what CI scans;
# other local branches and refs do not fail it. The working tree is scanned through git
# (--pre-commit for tracked changes, --staged for the index), never `gitleaks dir`, which reads
# gitignored files such as the lab's env and secret files.
leaks: bin/gitleaks-$(GITLEAKS_VERSION)
	bin/gitleaks-$(GITLEAKS_VERSION) git $(GITLEAKS_FLAGS) --log-opts=HEAD .
	bin/gitleaks-$(GITLEAKS_VERSION) git --pre-commit $(GITLEAKS_FLAGS) .
	bin/gitleaks-$(GITLEAKS_VERSION) git --staged $(GITLEAKS_FLAGS) .

# The fsGroup cell's red run: the same install with the first design's 2755 volume root, by the
# test-only post-renderer. The test PASSES only when the broker's second generation crash-loops on
# the exact state_dir refusal (a green broker, or a crash for another reason, fails it), so a passing
# target is the red result observed. It builds the setup image the test loads, and deletes the
# cluster afterwards like kind-smoke.
kind-smoke-red: image build bin/kind-v$(KIND_VERSION) bin/kubectl-$(KUBECTL_VERSION) bin/helm-$(HELM_VERSION)
	docker build --target setup -t port49-setup:dev .
	go build -o bin/oldroot ./tests/kind/cmd/oldroot
	rc=0; KIND_OLD_ROOT=1 KIND_BIN=$(CURDIR)/bin/kind-v$(KIND_VERSION) KUBECTL_BIN=$(CURDIR)/bin/kubectl-$(KUBECTL_VERSION) \
	  HELM_BIN=$(CURDIR)/bin/helm-$(HELM_VERSION) OLDROOT_BIN=$(CURDIR)/bin/oldroot \
	  go test -tags kind ./tests/kind/ -run TestKindSmoke -count=1 -v -timeout 40m || rc=$$?; \
	  $(CURDIR)/bin/kind-v$(KIND_VERSION) delete cluster --name port49smoke; exit $$rc

# The systemd shape end to end (plan 12b, Task 9): the port49-server package from `make packages`
# installed in a Debian container whose PID 1 is systemd. UNVERIFIED: not run. Needs Docker with
# --privileged and a cgroup v2 host. It builds tests/systemd/Dockerfile (apt and the etcd image
# are pulled by that build) and fails, never skips, when dist/ holds no package.
systemd-smoke: packages
	go test -tags systemd ./tests/systemd/ -count=1 -v -timeout 30m
