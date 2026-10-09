#!/bin/bash
W=$(cat /tmp/l51.workdir); stamp() { date +%T; }
echo "-- $(stamp) 3 failed password sessions as alice15"
for n in 1 2 3; do $W/probe.sh PT$n alice15 -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive >/dev/null 2>&1; done
T0=$(date +%s)
for d in 0 30 60 90 120 150 180; do now=$(( $(date +%s) - T0 )); [ $now -lt $d ] && sleep $(( d - now ))
  echo "-- $(stamp) +${d}s alice15 token: $($W/tok.sh PTL$d alice15 -o PubkeyAuthentication=no | cut -d: -f2- | cut -c1-130)"; done
