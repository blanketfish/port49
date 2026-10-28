#!/usr/bin/env bash
# The break-glass revoke: with every broker stopped, as the broker's own user.
#
#   revoke-offline.sh <namespace> <release> -- <port49-broker revoke flags>
#   revoke-offline.sh prod port49 -- --principal user:bob@example.com
#   revoke-offline.sh prod port49 -- --principal user:bob@example.com --lift
#   revoke-offline.sh prod port49 -- --list
#
# For when no admin can use the API (README, "Admin operations"). It scales the broker
# StatefulSet to 0 (so no broker serves while it runs), runs `port49-broker revoke --offline` in a
# one-shot pod on broker-0's PVC and config, and scales back to the count it found, on every exit.
# If a controller (a GitOps tool, an HPA) holds the replica count it will scale it back itself.
# Every pod it starts is deleted on every exit.
set -euo pipefail

ns=${1:?usage: revoke-offline.sh <namespace> <release> -- <revoke flags>}
rel=${2:?usage: revoke-offline.sh <namespace> <release> -- <revoke flags>}
shift 2
[ "${1:-}" = -- ] || { echo "usage: revoke-offline.sh <namespace> <release> -- <revoke flags>" >&2; exit 2; }
shift
[ "$#" -gt 0 ] || { echo "usage: revoke-offline.sh <namespace> <release> -- <revoke flags>" >&2; exit 2; }
sts=$rel-broker
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$here/lib.sh"

replicas=$(sts_field '{.spec.replicas}')
[ -n "$replicas" ] || die "no StatefulSet $sts in namespace $ns"

# broker-0's node, read before its pod goes.
prime_node 0

scaled=
restore() {
  [ -z "$scaled" ] || K scale "statefulset/$sts" --replicas="$replicas" >/dev/null
  cleanup
}
trap restore EXIT

args='["revoke","--offline","--config","/etc/port49/config/port49-broker.yaml"'
for a in "$@"; do
  # a JSON string: escape the two characters that need it
  a=${a//\\/\\\\}
  a=${a//\"/\\\"}
  args+=",\"$a\""
done
args+=']'

echo "stopping the brokers (replicas $replicas -> 0)"
scaled=1
K scale "statefulset/$sts" --replicas=0 >/dev/null
K wait --for=delete pod -l "app.kubernetes.io/name=port49,app.kubernetes.io/instance=$rel,app.kubernetes.io/component=broker" --timeout=120s >/dev/null

run=$sts-revoke-$$
broker_pod 0 "$run" '["/usr/local/bin/port49-broker"]' "$args"
status=0
finish "$run" || status=$?
echo "starting the brokers (replicas 0 -> $replicas)"
exit "$status"
