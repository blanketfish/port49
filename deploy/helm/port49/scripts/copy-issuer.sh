#!/usr/bin/env bash
# Makes the issuing CA once, and copies it to the other brokers; never replaces a CA.
#
#   copy-issuer.sh <namespace> <release> --from <ordinal> [--to <ordinal>]...
#   copy-issuer.sh prod port49 --from 0              # first install: make it on broker-0, copy to the rest
#   copy-issuer.sh prod port49 --from 1 --to 0       # broker-0's volume was lost: copy from a broker that holds it
#
# Every broker of a release must hold the same issuing CA or it refuses to start against the store's
# record of it. --from names the broker whose CA is the one to keep; --to names the brokers that get it
# (default: every other broker). The script looks at every broker's volume first, from read-only
# one-shot pods on each PVC's node (never `kubectl exec` into a broker: it may be the one crash-looping,
# and its image has no shell), then:
#   - the source holds no CA and no other broker does: `port49-broker init-issuer` runs on the source;
#   - the source holds none but another broker does: it REFUSES and names that broker. A second
#     init-issuer would make a different CA and every broker would then refuse to start;
#   - a target holds the same CA (and previous CA): skipped;
#   - a target holds a different CA: it REFUSES, naming both ordinals and both certificate sha256s.
#     Every target's CA is compared before the first copy. What is left to a target's own copy step is
#     a stray file of that target's (a key with no certificate): the copy refuses any name that exists,
#     so an earlier target may already hold its copy by then. A copy never replaces a file.
# issuing-ca.pem and issuing-ca.key, and issuing-ca-previous.pem when the source has it, are streamed
# in one kubectl exec into a staging directory on the target, then renamed into place only where the
# name is free; the key is written 0600, owned by 65532. Every pod it starts is deleted (waited for) on
# every exit and has a deadline. Then it restarts the brokers and prints each one's issuing CA line.
set -euo pipefail

usage() {
  echo "usage: copy-issuer.sh <namespace> <release> --from <ordinal> [--to <ordinal>]..." >&2
  exit 2
}
[ "$#" -ge 2 ] || usage
ns=$1
rel=$2
shift 2
from=
tos=()
while [ "$#" -gt 0 ]; do
  case $1 in
    --from) [ "$#" -ge 2 ] || usage; from=$2; shift 2 ;;
    --to) [ "$#" -ge 2 ] || usage; tos+=("$2"); shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$from" ] || usage
for o in "$from" ${tos[@]+"${tos[@]}"}; do
  [[ $o =~ ^[0-9]+$ ]] || usage
done
sts=$rel-broker
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$here/lib.sh"

replicas=$(sts_field '{.spec.replicas}')
[ -n "$replicas" ] || die "no StatefulSet $sts in namespace $ns"
[ "$from" -lt "$replicas" ] || die "--from $from: the StatefulSet has $replicas brokers (0 to $((replicas - 1)))"
if [ "${#tos[@]}" -eq 0 ]; then
  for ((i = 0; i < replicas; i++)); do [ "$i" -eq "$from" ] || tos+=("$i"); done
fi
for t in ${tos[@]+"${tos[@]}"}; do
  [ "$t" -lt "$replicas" ] || die "--to $t: the StatefulSet has $replicas brokers (0 to $((replicas - 1)))"
  [ "$t" -ne "$from" ] || die "--to $t is the --from broker"
done

# What each broker's volume holds: the sha256 of issuing-ca.pem and issuing-ca-previous.pem ("" when
# absent). Certificates only: the key is never hashed or printed.
pem=()
prev=()
inspect() { # ordinal
  local ord=$1 name out sum file
  name=$sts-inspect-$ord-$$
  shell_pod "$ord" "$name" /s true
  # No state/ is an empty volume; a read that fails is an error, never "absent" (a misread CA would
  # let init-issuer or a copy act on a volume that holds one).
  out=$(K exec "$name" -- sh -c '[ -d /s/state ] || exit 0; cd /s/state || exit 1
for f in issuing-ca.pem issuing-ca-previous.pem; do [ ! -f "$f" ] || sha256sum "$f" || exit 1; done') ||
    die "could not read broker-$ord's volume (the sha256 of its issuing CA failed). Nothing was changed."
  K delete pod "$name" --ignore-not-found --wait=true >/dev/null
  pem[ord]=
  prev[ord]=
  while read -r sum file; do
    case $file in
      *issuing-ca-previous.pem) prev[ord]=$sum ;;
      *issuing-ca.pem) pem[ord]=$sum ;;
    esac
  done <<<"$out"
}
for ((i = 0; i < replicas; i++)); do inspect "$i"; done

changed=
if [ -z "${pem[from]}" ]; then
  for ((i = 0; i < replicas; i++)); do
    [ -z "${pem[i]}" ] || die "broker-$from holds no issuing CA, but broker-$i does (sha256 ${pem[i]}). init-issuer would make a second, different CA and every broker would refuse to start against the store's record. Copy the one that exists: --from $i"
  done
  echo "init-issuer on broker-$from's volume"
  run=$sts-issuer-$$
  broker_pod "$from" "$run" '["/usr/local/bin/port49-broker"]' \
    '["init-issuer","--config","/etc/port49/config/port49-broker.yaml"]'
  finish "$run" || die "init-issuer failed; its log is above. Nothing was copied."
  K delete pod "$run" --ignore-not-found --wait=true >/dev/null
  inspect "$from"
  [ -n "${pem[from]}" ] || die "init-issuer ran but broker-$from's volume holds no issuing-ca.pem"
  changed=1
fi

# Every target is checked before any is touched.
need=()
for t in ${tos[@]+"${tos[@]}"}; do
  need[t]=
  if [ -n "${pem[t]}" ] && [ "${pem[t]}" != "${pem[from]}" ]; then
    die "refusing: broker-$t holds issuing CA sha256 ${pem[t]}, broker-$from holds sha256 ${pem[from]}. A broker's CA is never overwritten. Copy from the broker that holds the CA the store records (--from <ordinal>, and its log's issuing CA line). forget-issuer is not the way out: it removes the store's record and every certificate issued under the old CA stops working."
  fi
  if [ -n "${prev[from]}" ] && [ -n "${prev[t]}" ] && [ "${prev[t]}" != "${prev[from]}" ]; then
    die "refusing: broker-$t holds previous issuing CA sha256 ${prev[t]}, broker-$from holds sha256 ${prev[from]}. Nothing was changed."
  fi
  [ -n "${pem[t]}" ] || need[t]="issuing-ca.pem issuing-ca.key"
  if [ -n "${prev[from]}" ] && [ -z "${prev[t]}" ]; then need[t]="${need[t]:+${need[t]} }issuing-ca-previous.pem"; fi
done

for t in ${tos[@]+"${tos[@]}"}; do
  if [ -z "${need[t]}" ]; then
    echo "broker-$t already holds this issuing CA; skipped"
    continue
  fi
  src=$sts-copy-src-$t-$$
  dst=$sts-copy-dst-$t-$$
  echo "copying to broker-$t (${need[t]})"
  shell_pod "$from" "$src" /s true
  shell_pod "$t" "$dst" /d false
  # Staged, then renamed where the name is free: a broken stream leaves .copy-issuer, not a partial key.
  # shellcheck disable=SC2086 # the file list is words
  K exec "$src" -- tar c -C /s/state ${need[t]} |
    K exec -i "$dst" -- sh -c 'set -eu; umask 077; d=/d/state; s=$d/.copy-issuer
install -d -o 65532 -g 65532 -m 0700 "$d"
rm -rf "$s"; install -d -m 0700 "$s"
tar x -C "$s"
# this runs as root: a link in the stream is refused before anything follows it, and so is anything
# that is not a regular file (a directory named like a key arrives with whatever links it holds)
for f in "$s"/*; do
  [ ! -L "$f" ] || { echo "${f##*/} is a symbolic link: not copied" >&2; exit 1; }
  [ -f "$f" ] || { echo "${f##*/} is not a regular file: not copied" >&2; exit 1; }
done
for f in "$s"/*; do [ ! -e "$d/${f##*/}" ] || { echo "$d/${f##*/} exists: not replaced" >&2; exit 1; }; done
chown -h 65532:65532 "$s"/*
[ ! -e "$s/issuing-ca.key" ] || chmod 0600 "$s/issuing-ca.key"
for n in issuing-ca-previous.pem issuing-ca.key issuing-ca.pem; do
  [ -e "$s/$n" ] || continue
  want=$(sha256sum < "$s/$n")
  mv -n "$s/$n" "$d/$n"
  [ ! -e "$s/$n" ] && [ "$(sha256sum < "$d/$n")" = "$want" ] || { echo "$d/$n was not placed: not replaced" >&2; exit 1; }
done
rmdir "$s"'
  K delete pod "$src" "$dst" --ignore-not-found --wait=true >/dev/null
  changed=1
done

if [ -n "$changed" ]; then
  echo "restarting the brokers to read the CA"
  K rollout restart "statefulset/$sts" >/dev/null
  K rollout status "statefulset/$sts" --timeout=300s
else
  echo "every target already holds this issuing CA; nothing changed"
fi
for ((i = 0; i < replicas; i++)); do
  echo "broker-$i:"
  K logs "$sts-$i" 2>&1 | grep -i 'issuing ca' || echo "  (no issuing CA line yet: kubectl -n $ns logs $sts-$i)"
done
