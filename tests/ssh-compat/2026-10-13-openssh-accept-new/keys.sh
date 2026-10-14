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
#
# A hop ssh gets only -F from the top ssh, not its -o options, so the hop's trust is seeded through a
# -F cfg: its known_hosts line (the plain name on port 22, [name]:port otherwise) and
# StrictHostKeyChecking yes, so the hop reaches its password prompt and the askpass never meets a
# host-key question. The three runs:
#   g1c-hostkey  the hop's host key is unknown (empty file, ask): the hop's host-key question
#   g1c          the hop's key is known: the hop's password prompt (the gate)
#   g1c-control  no -J, the device's own password prompt: its parent must be the top ssh
cp "$(dirname "$0")/askpass.sh" "$T/ap" && chmod +x "$T/ap"
hn=127.0.0.1; [ "$P22" = 22 ] || hn="[127.0.0.1]:$P22"
printf '%s %s\n' "$hn" "$(k ed25519)" > "$T/kh-hop"
: > "$T/kh-empty"
printf 'Host 127.0.0.1\n  UserKnownHostsFile %s\n  GlobalKnownHostsFile /dev/null\n  StrictHostKeyChecking yes\n' "$T/kh-hop" > "$T/pjcfg"
printf 'Host 127.0.0.1\n  UserKnownHostsFile %s\n  GlobalKnownHostsFile /dev/null\n  StrictHostKeyChecking ask\n' "$T/kh-empty" > "$T/pjcfg-ask"
pj() { # name cfg ssh-args...: run ssh in the background so $! is the top ssh, log every asker
  name=$1 cfg=$2; shift 2
  : > "$T/askers-$name"
  ASKLOG="$T/askers-$name" SSH_ASKPASS="$T/ap" SSH_ASKPASS_REQUIRE=force ssh -F "$cfg" -o IdentitiesOnly=yes \
      -i "$CTL" -o PreferredAuthentications=keyboard-interactive,password -o NumberOfPasswordPrompts=1 \
      "$@" true 2>"$T/err-$name" &
  top=$!; wait "$top"
  echo "== $name: top ssh $top"
  awk -F'\t' '{print "  asker " $1 ": " $2 "| prompt: " $3}' "$T/askers-$name"
}
pj g1c-hostkey "$T/pjcfg-ask" -J "jumpuser@127.0.0.1:$P22" -p "$P2222" tuser@127.0.0.1
echo "  asker parents: $(cut -f1 "$T/askers-g1c-hostkey" | sort -u | tr '\n' ' ')(recorded, not a gate)"
pj g1c "$T/pjcfg" -J "jumpuser@127.0.0.1:$P22" -p "$P2222" tuser@127.0.0.1
gtop=$top
if grep -q "password: " "$T/askers-g1c" && ! cut -f1 "$T/askers-g1c" | grep -qx "$gtop"; then g1c=PASS; else g1c=FAIL; fi
pj g1c-control "$T/pjcfg" -p "$P22" jumpuser@127.0.0.1
if grep -q "password: " "$T/askers-g1c-control" && cut -f1 "$T/askers-g1c-control" | grep -qx "$top"; then ctl=PASS; else ctl=FAIL; fi
echo "  g1c-control: $ctl"
if [ "$ctl" = PASS ]; then echo "  g1c: $g1c"; else echo "  g1c: INVALID (control $ctl; cell $g1c)"; fi
ssh-keygen -q -k -f "$T/krl" "$T/other.pub"
for cfg in "" "StrictHostKeyChecking yes" "StrictHostKeyChecking no" "StrictHostKeyChecking ask" \
    "StrictHostKeyChecking accept-new" "StrictHostKeyChecking off" "Host leaf1
  HostKeyAlias Corp-Leaf1" "UserKnownHostsFile /dev/null" "UserKnownHostsFile none" \
    "RevokedHostKeys $T/krl" "KnownHostsCommand /bin/true %H" "Match user alice
  HostKeyAlias alice-leaf1" "HashKnownHosts yes" \
    "UserKnownHostsFile ~/kh1 %d/kh2 /etc/kh3
GlobalKnownHostsFile ~/g1 %d/g2" 'UserKnownHostsFile "/a b/kh" /c/kh'; do
  printf '%s\n' "$cfg" > "$T/cfg"
  for dest in leaf1 Leaf1; do
    echo "== g-forms [$(echo "$cfg" | tr '\n' ';')] $dest:"
    ssh -G -F "$T/cfg" -o 'HostName="fe80::1%%eth0"' -l alice -- "$dest" |
      grep -E '^(stricthostkeychecking|hostkeyalias|userknownhostsfile|globalknownhostsfile|hashknownhosts|revokedhostkeys|knownhostscommand) ' |
      sed 's/^/  /'
  done
done
