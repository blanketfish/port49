#!/usr/bin/env bash
# Makes the issuing CA once, on broker-0, and copies it to every other broker.
#
#   copy-issuer.sh <namespace> <release>
#
# Every broker of a release must hold the same issuing CA or it refuses to start. This runs
# `port49-broker init-issuer` in a one-shot pod on broker-0's PVC (never `kubectl exec` into
# broker-0, which may be the one crash-looping), then copies issuing-ca.pem and issuing-ca.key to
# every other broker's PVC: each side is a root debug pod on that PVC's node, because `kubectl cp`
# cannot work against a distroless broker. The key travels inside one kubectl exec stream and is
# written 0600, owned by 65532. Every pod it starts is deleted on every exit. Then it restarts the
# brokers and prints each one's issuing CA line.
set -euo pipefail

ns=${1:?usage: copy-issuer.sh <namespace> <release>}
rel=${2:?usage: copy-issuer.sh <namespace> <release>}
sts=$rel-broker
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$here/lib.sh"

replicas=$(sts_field '{.spec.replicas}')
[ -n "$replicas" ] || die "no StatefulSet $sts in namespace $ns"
run=$sts-issuer-$$

echo "init-issuer on broker-0's volume"
broker_pod 0 "$run" '["/usr/local/bin/port49-broker"]' \
  '["init-issuer","--config","/etc/port49/config/port49-broker.yaml"]'
finish "$run" || die "init-issuer failed; its log is above. Nothing was copied."

for ((i = 1; i < replicas; i++)); do
  src=$sts-copy-src-$$
  dst=$sts-copy-dst-$i-$$
  echo "copying to broker-$i"
  shell_pod 0 "$src" /s true
  shell_pod "$i" "$dst" /d false
  K exec "$src" -- tar c -C /s/state issuing-ca.pem issuing-ca.key |
    K exec -i "$dst" -- sh -c 'install -d -o 65532 -g 65532 -m 0700 /d/state && tar x -C /d/state && chown 65532:65532 /d/state/issuing-ca.* && chmod 0600 /d/state/issuing-ca.key'
  K delete pod "$src" "$dst" --ignore-not-found --wait=true >/dev/null
done

echo "restarting the brokers to read the CA"
K rollout restart "statefulset/$sts" >/dev/null
K rollout status "statefulset/$sts" --timeout=300s
for ((i = 0; i < replicas; i++)); do
  echo "broker-$i:"
  K logs "$sts-$i" 2>&1 | grep -i 'issuing ca' || echo "  (no issuing CA line yet: kubectl -n $ns logs $sts-$i)"
done
