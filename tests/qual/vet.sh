#!/usr/bin/env bash
# make qual-vet P=<selector>: vet a firmware and generate its mock for review (plan 11b).
# Commits nothing: the review of the generated profile is a person's.
set -euo pipefail
sel="${1:?usage: make qual-vet P=<selector>}"
[ -e /tmp/port49-STOP-LAB ] && { echo "qual-vet: /tmp/port49-STOP-LAB exists"; exit 1; }
flock -n /tmp/port49-lab.lock true || { echo "qual-vet: the lab is occupied ($(cat /tmp/port49-lab.lock))"; exit 1; }
[ -z "$(git status --porcelain -- tests/qual tests/lab/results)" ] || { echo "qual-vet: commit or stash tests/qual and tests/lab/results first"; exit 1; }
log="/tmp/claude-qual-vet-${sel}-$(date +%s).log"
filter() { grep -v -i 'password\|token\|secret\|eyJ' | sed -E 's/[A-Za-z0-9_+\/=.-]{24,}/<LONG>/g'; }
make lab-qualify P="$sel" >"$log" 2>&1 || { tail -40 "$log" | filter; exit 1; }
filter <"$log" | grep -E '^(--- |ok |FAIL)' || true
# the evidence directory this run wrote: the newest QUAL-* directory touched since the log began
ev=$(find tests/lab/evidence -maxdepth 1 -type d -name 'QUAL-*' -newer "$log" -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-)
[ -n "$ev" ] || { echo "qual-vet: lab-qualify wrote no tests/lab/evidence/QUAL-* directory"; exit 1; }
go run ./tests/qual/cmd/genprofile -evidence "$ev"
make qual
make qualified-platforms
git status --short -- tests/qual tests/lab/results tests/lab/evidence docs/qualified-platforms.md
git diff --stat -- tests/qual docs/qualified-platforms.md
echo "qual-vet: review the profile against its note (the checklist above), then commit."
