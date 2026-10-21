#!/usr/bin/env bash
# make qual-vet P=<selector>: vet a firmware and generate its mock for review (plan 11b).
# Commits nothing: the review of the generated profile is a person's.
set -euo pipefail
sel="${1:?usage: make qual-vet P=<selector>}"
[ -e /tmp/port49-STOP-LAB ] && { echo "qual-vet: /tmp/port49-STOP-LAB exists"; exit 1; }
flock -n /tmp/port49-lab.lock true || { echo "qual-vet: the lab is occupied ($(cat /tmp/port49-lab.lock))"; exit 1; }
[ -z "$(git status --porcelain -- tests/qual tests/lab/results)" ] || { echo "qual-vet: commit or stash tests/qual and tests/lab/results first"; exit 1; }
log="/tmp/claude-qual-vet-${sel}-$(date +%s).log"
# the log may hold what the run printed: owner-only. The umask stays the default, because
# containerlab's lab directory is read by the node's own uid (SR Linux cannot read a 0600 config).
(umask 077; : >"$log")
# the marker predates the run, so the run's evidence directory is newer than it
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
marker="$tmp/start"; touch "$marker"
filter() { grep -v -i 'password\|token\|secret\|eyJ' | sed -E 's/[A-Za-z0-9_+\/=.-]{24,}/<LONG>/g'; }
make lab-qualify P="$sel" >"$log" 2>&1 || { tail -40 "$log" | filter; exit 1; }
filter <"$log" | grep -E '^(--- |ok |FAIL)' || true
# the evidence directory this run wrote: the newest QUAL-* directory created since the run began
ev=$(find tests/lab/evidence -maxdepth 1 -type d -name 'QUAL-*' -newer "$marker" -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-)
[ -n "$ev" ] || { echo "qual-vet: lab-qualify wrote no tests/lab/evidence/QUAL-* directory"; exit 1; }
# GENPROFILE_FLAGS: -keep=<key,...> / -take=<key,...> for a conflict genprofile names (hand refinements it must not overwrite)
go run ./tests/qual/cmd/genprofile -evidence "$ev" ${GENPROFILE_FLAGS:-}
# the list first: make qual fails while the committed page is stale
make qualified-platforms
make qual
git status --short -- tests/qual tests/lab/results tests/lab/evidence docs/qualified-platforms.md
git diff --stat -- tests/qual docs/qualified-platforms.md
echo "qual-vet: the raw lab log is $log (unfiltered; read it only through the secret filter)"
echo "qual-vet: review the profile against its note (the checklist above), then commit."
