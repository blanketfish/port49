#!/bin/bash
# snap.sh <label> : device state via the long-lived console session
W=$(cat /tmp/l51.workdir); lab=$1
echo "##### SNAP $lab $(date +%T)" >> $W/out/xe-console.txt
for c in 'show aaa servers' 'show tacacs' 'show logging | include TACACS|AAA|SSH|DOT1X'; do printf '%s\r' "$c" > $W/in; sleep 3; done
printf '##### END %s\r' "$lab" > $W/in; sleep 1
