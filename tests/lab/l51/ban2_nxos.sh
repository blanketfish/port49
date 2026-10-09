#!/bin/bash
W=$(cat /tmp/l51.workdir); ids=(); for i in 1 2 3; do ids+=(-i $W/k$i); done
stamp() { date +%T; }
login() { u=$1; label=$2; $W/tok.sh $label $u -o PubkeyAuthentication=no | cut -c1-175; }
echo "-- $(stamp) POSITIVE CONTROL: 3 failed password sessions (garbage), no keys"
for n in 1 2 3; do $W/probe.sh PC$n alice11 -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive 2>&1 | grep -E '^==|Permission|closed' | cut -c1-120; done
T0=$(date +%s)
echo "-- $(stamp) +0s same user (alice11)"; login alice11 PCban-same
echo "-- $(stamp) +0s other user (alice12)"; login alice12 PCban-other
echo "-- $(stamp) wait until +200s for the ban to lapse"; now=$(( $(date +%s) - T0 )); sleep $(( 200 - now ))
echo "-- $(stamp) 3 connections x 3 refused keys, within 60s"
for n in 1 2 3; do $W/probe.sh KEYS$n alice13 -o IdentitiesOnly=yes "${ids[@]}" 2>&1 | grep -E '^==|Too many' | cut -c1-120; done
echo "-- $(stamp) +0s same user (alice13)"; login alice13 Kban-same
echo "-- $(stamp) +0s other user (alice14)"; login alice14 Kban-other
