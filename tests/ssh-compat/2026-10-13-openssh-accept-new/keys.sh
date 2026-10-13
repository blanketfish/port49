#!/bin/sh
# Plan 9d Task 2's cells. KEYS is where the server's public keys are (the
# container's /etc/ssh; a copy for the host's client), CTL the client key,
# P22 and P2222 the two servers' ports.
KEYS=${KEYS:-/etc/ssh} CTL=${CTL:-/root/.ssh/ctl} P22=${P22:-22} P2222=${P2222:-2222}
T=$(mktemp -d) # a rerun meets no earlier run's keys (pre-flight nit)
k() { cut -d' ' -f1,2 "$KEYS/ssh_host_$1_key.pub"; }
cell() { # name port kh-contents [ssh options...]
  name=$1 port=$2 lines=$3; shift 3
  printf '%s' "$lines" > "$T/kh"
  ssh -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o HostKeyAlias=leaf1 \
      -o UserKnownHostsFile="$T/kh" -o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes -i "$CTL" \
      -o PreferredAuthentications=publickey -p "$port" "$@" tuser@127.0.0.1 true 2>"$T/err"
  echo "== $name: exit $?"
  tail -n 3 "$T/err" | sed 's/^/  stderr: /'
  sed 's/^/  kh: /' "$T/kh"
}
ssh-keygen -q -t ed25519 -N '' -f "$T/other"
cell g1 "$P2222" "leaf1 $(k ecdsa)
"
cell g1-control "$P2222" ""
cell g1b "$P22" "leaf1 $(k ecdsa)
" -o HostKeyAlgorithms=ssh-ed25519
cell changed-same-type "$P22" "leaf1 $(cut -d' ' -f1,2 "$T/other.pub")
"
cell hashed "$P22" "" -o HashKnownHosts=yes
echo "  hashed found: $(ssh-keygen -F leaf1 -f "$T/kh" | grep -vc '^#')"
# g1c (pre-flight N3): who is the askpass's parent when a ProxyJump hop asks? SSH_ASKPASS logs its own
# parent pid, then fails. The top ssh is this shell's background job, so $top is its pid.
printf '#!/bin/sh\necho "$PPID" >> "%s/askers"\nexit 1\n' "$T" > "$T/ap" && chmod +x "$T/ap" && : > "$T/askers"
SSH_ASKPASS="$T/ap" SSH_ASKPASS_REQUIRE=force ssh -F /dev/null -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile="$T/kh-pj" -o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes -i "$CTL" \
    -o PreferredAuthentications=keyboard-interactive,password -o NumberOfPasswordPrompts=1 \
    -J "jumpuser@127.0.0.1:$P22" -p "$P2222" tuser@127.0.0.1 true 2>"$T/err-pj" &
top=$!; wait "$top"
echo "== g1c: top ssh $top; askpass parents: $(sort -u "$T/askers" | tr '\n' ' ')"
if [ -s "$T/askers" ] && ! grep -qx "$top" "$T/askers"; then echo "  g1c: PASS"; else echo "  g1c: FAIL"; fi
ssh-keygen -q -k -f "$T/krl" "$T/other.pub"
for cfg in "" "StrictHostKeyChecking yes" "StrictHostKeyChecking no" "StrictHostKeyChecking ask" \
    "StrictHostKeyChecking accept-new" "StrictHostKeyChecking off" "Host leaf1
  HostKeyAlias Corp-Leaf1" "UserKnownHostsFile /dev/null" "UserKnownHostsFile none" \
    "RevokedHostKeys $T/krl" "KnownHostsCommand /bin/true %H" "Match user alice
  HostKeyAlias alice-leaf1" "HashKnownHosts yes" \
    "UserKnownHostsFile ~/kh1 %d/kh2 /etc/kh3
GlobalKnownHostsFile ~/g1 %d/g2"; do
  printf '%s\n' "$cfg" > "$T/cfg"
  for dest in leaf1 Leaf1; do
    echo "== g-forms [$(echo "$cfg" | tr '\n' ';')] $dest:"
    ssh -G -F "$T/cfg" -o 'HostName="fe80::1%%eth0"' -l alice -- "$dest" |
      grep -E '^(stricthostkeychecking|hostkeyalias|userknownhostsfile|globalknownhostsfile|hashknownhosts|revokedhostkeys|knownhostscommand) ' |
      sed 's/^/  /'
  done
done
