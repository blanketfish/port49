#!/bin/bash
# ban.sh : login-ban case. env: ADDR L51_NAS REMOTE_CMD NKEYS(default 3) SETTLE
W=$(cat /tmp/l51.workdir); ids=(); for i in $(seq 1 ${NKEYS:-3}); do ids+=(-i $W/k$i); done
stamp() { date +%T; }
echo "-- $(stamp) control: 2 refused keys, no password offered"
CMD="${REMOTE_CMD:-show hostname}" $W/ssh.sh garbage alice09 $ADDR -o IdentitiesOnly=yes -i $W/k1 -i $W/k2 -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o BatchMode=yes -o LogLevel=ERROR 2>&1 | tail -1 | cut -c1-120
$W/tok.sh C0 alice10 -o PubkeyAuthentication=no | cut -c1-170
echo "-- $(stamp) wait 70s to leave the 60s window"; sleep 70
echo "-- $(stamp) TRIGGER: one connection, ${NKEYS:-3} refused keys, garbage never typed"
$W/probe.sh TRIG alice01 -o IdentitiesOnly=yes "${ids[@]}" 2>&1 | grep -E '^==|Too many|Connection closed|Permission denied|disconnect'
T0=$(date +%s)
login() { u=$1; label=$2; $W/tok.sh $label $u -o PubkeyAuthentication=no | cut -c1-175; }
echo "-- $(stamp) +0s same user (alice01)"; login alice01 B0-sameuser
echo "-- $(stamp) +0s other user (alice02)"; login alice02 B0-otheruser
for d in 30 60 120 180; do
  now=$(( $(date +%s) - T0 )); [ $now -lt $d ] && sleep $(( d - now ))
  u=alice0$(( 2 + d/30 > 9 ? 9 : 2 + d/30 ))
  echo "-- $(stamp) +${d}s (as $u)"; login $u B$d
done
