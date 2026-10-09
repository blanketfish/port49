#!/bin/bash
W=$(cat /tmp/l51.workdir); n=0
ids=(); for i in 1 2 3 4 5 6; do ids+=(-i $W/k$i); done
for d in ${DELAYS:-0 30 60 120 300}; do n=$((n+1)); u=alice$(printf %02d $((${UBASE:-6}+n)))
 $W/probe.sh LOCK-refuse-$u $u -o IdentitiesOnly=yes "${ids[@]}" 2>&1 | grep -E '^==|Too many'
 sleep $d; : > $W/prompts.log
 echo "-- $(date +%T) token login as $u after ${d}s"
 CMD="${REMOTE_CMD:-show hostname}" $W/ssh.sh token $u ${ADDR:-172.100.100.31} -v -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 > $W/out/LOCK-$u.raw 2>&1
 grep -E 'Authenticated to|Permission denied|Too many|Connection (closed|reset)|Next authentication' $W/out/LOCK-$u.raw; tail -2 $W/out/LOCK-$u.raw | sed 's/^debug1.*//' | grep -v '^$'
done
