#!/bin/bash
# tok.sh <label> <user> <ssh opts...> : real token, reports login result
W=$(cat /tmp/l51.workdir); label=$1; user=$2; shift 2; : > $W/prompts.log
CMD="${REMOTE_CMD:-show hostname}" $W/ssh.sh token $user ${ADDR:-172.100.100.31} -v -o NumberOfPasswordPrompts=1 -o IdentityFile=none "$@" > $W/out/$label.raw 2>&1
echo "== $label as $user: offers=$(grep -c 'Offering public key' $W/out/$label.raw) prompts=$(wc -l < $W/prompts.log) result: $(grep -E 'Authenticated to|Too many|Permission denied' $W/out/$label.raw | sed 's/^debug1: //;s/alice[0-9]*@//' | head -1 | cut -c1-110)"
sleep 4
