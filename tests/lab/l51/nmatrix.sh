#!/bin/bash
W=$(cat /tmp/l51.workdir); keys=${KEYS:-k}
for n in $(seq 1 ${NMAX:-6}); do ids=(); for i in $(seq 1 $n); do ids+=(-i $W/$keys$i); done
 $W/probe.sh ${LABEL:-N}$n alice$(printf %02d $n) -o IdentitiesOnly=yes "${ids[@]}" 2>&1 | grep -E '^==|Offering|Too many|Next authentication method: (keyboard|password)'; sleep 5; done
