#!/bin/bash
# probe.sh <label> <user> <ssh opts...>  : garbage-password probe, -v auth lines kept
W=$(cat /tmp/l51.workdir); label=$1; user=$2; shift 2; : > $W/prompts.log
CMD="${REMOTE_CMD:-show hostname}" $W/ssh.sh garbage $user ${ADDR:-172.100.100.31} -v -o NumberOfPasswordPrompts=1 "$@" > $W/out/$label.raw 2>&1
echo "== $label (prompts reached: $(wc -l < $W/prompts.log))"
grep -E "Offering public key|Offering .* certificate|Authentications that can continue|Next authentication method|Too many|Permission denied|Disconnected|Connection (closed|reset)|Authenticated to|Will attempt key|identity file|certificate file" $W/out/$label.raw | sed 's#/tmp/l51\.[A-Za-z0-9]*/#<W>/#g' | cut -c1-200
