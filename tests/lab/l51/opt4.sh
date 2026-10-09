#!/bin/bash
W=$(cat /tmp/l51.workdir); export ADDR=172.100.100.41 L51_NAS=xe1 REMOTE_CMD='show privilege'
# agent.sock holds k1..k5 + kc(+cert) = 7 identities
AGENT=$W/agent.sock $W/tok.sh O4a-retries5-7ids alice01 -o IdentityFile=none | cut -c1-170; sleep 4
grep -E 'Offering' $W/out/O4a-retries5-7ids.raw | sed 's/^debug1: //;s/ SHA256:[^ ]*//' | cut -c1-80
# 5 identities only
ssh-agent -a $W/agent5.sock > /dev/null; for i in 1 2 3 4 5; do SSH_AUTH_SOCK=$W/agent5.sock ssh-add -q $W/k$i; done
for t in 1 2 3; do AGENT=$W/agent5.sock $W/tok.sh O4b-retries5-5ids-try$t alice13 -o IdentityFile=none | cut -c1-170; sleep 8; done
SSH_AUTH_SOCK=$W/agent5.sock ssh-agent -k >/dev/null
