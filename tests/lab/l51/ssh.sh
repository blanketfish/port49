#!/bin/bash
# usage: CMD='remote cmd' ssh.sh <askpass-mode> <user> <addr> <ssh opts...>
W=$(cat /tmp/l51.workdir); mode=$1; user=$2; addr=$3; shift 3
echo $mode > $W/mode; echo $user > $W/user
SSH_ASKPASS=$W/askpass.sh SSH_ASKPASS_REQUIRE=force DISPLAY=x SSH_AUTH_SOCK=${AGENT:-} L51_NAS=${L51_NAS:-nx1} \
 timeout 90 ssh -F ${SSHCONF:-/dev/null} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=20 "$@" $user@$addr $CMD
