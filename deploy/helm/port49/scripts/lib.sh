# Shared by copy-issuer.sh and revoke-offline.sh (sourced; sets nothing on its own).
# The scripts never use `kubectl exec` into a broker pod (it may be the one crash-looping, and the
# image has no shell): they start one-shot pods built from the broker StatefulSet's own pod spec,
# on the node that holds the PVC, and delete every pod they started on every exit.

# ns, rel and sts are set by the script before the first call.
K() { kubectl -n "$ns" "$@"; }
die() { echo "$(basename "$0"): $*" >&2; exit 1; }

started=()
cleanup() {
  local p
  for p in ${started[@]+"${started[@]}"}; do
    K delete pod "$p" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP

sts_field() { K get statefulset "$sts" -o jsonpath="$1"; }

# The node a broker's PVC lives on: the node of its pod when it runs, else the PV's node affinity,
# else empty (the scheduler places the pod, as it must for a network volume).
node_of() { # ordinal
  local n pv var="NODE_$1"
  if [ -n "${!var+x}" ]; then printf '%s' "${!var}"; return 0; fi
  n=$(K get pod "$sts-$1" -o jsonpath='{.spec.nodeName}' 2>/dev/null || true)
  if [ -z "$n" ]; then
    pv=$(K get pvc "data-$sts-$1" -o jsonpath='{.spec.volumeName}' 2>/dev/null || true)
    [ -z "$pv" ] || n=$(kubectl get pv "$pv" -o jsonpath='{.spec.nodeAffinity.required.nodeSelectorTerms[0].matchExpressions[0].values[0]}' 2>/dev/null || true)
  fi
  printf '%s' "$n"
}

# Remembers broker $1's node now, before a scale-down takes its pod away.
prime_node() { # ordinal
  local n
  n=$(node_of "$1")
  printf -v "NODE_$1" '%s' "$n"
}

# A pod from the broker StatefulSet's own spec (image, security context, initContainers, volumes
# and mounts, so every path matches the broker's), with its data volume pointing at the PVC of
# broker $1 and its command replaced.
broker_pod() { # ordinal name command-json args-json
  local ord=$1 name=$2 cmd=$3 args=$4 pvc node nodefrag image vols mounts psec csec init
  pvc="data-$sts-$ord"
  node=$(node_of "$ord")
  nodefrag=""
  if [ -n "$node" ]; then nodefrag="\"nodeName\":\"$node\","; fi
  image=$(sts_field '{.spec.template.spec.containers[0].image}')
  vols=$(sts_field '{.spec.template.spec.volumes}')
  mounts=$(sts_field '{.spec.template.spec.containers[0].volumeMounts}')
  psec=$(sts_field '{.spec.template.spec.securityContext}')
  csec=$(sts_field '{.spec.template.spec.containers[0].securityContext}')
  init=$(sts_field '{.spec.template.spec.initContainers}')
  vols="${vols%]},{\"name\":\"data\",\"persistentVolumeClaim\":{\"claimName\":\"$pvc\"}}]"
  started+=("$name")
  K apply -f - >/dev/null <<JSON
{"apiVersion":"v1","kind":"Pod","metadata":{"name":"$name","labels":{"app.kubernetes.io/name":"port49-oneshot"}},
 "spec":{"restartPolicy":"Never",${nodefrag}"automountServiceAccountToken":false,
  "securityContext":$psec,"initContainers":$init,"volumes":$vols,
  "containers":[{"name":"run","image":"$image","command":$cmd,"args":$args,
    "securityContext":$csec,"volumeMounts":$mounts}]}}
JSON
}

# A root debug pod on broker $1's PVC (alpine, as the chart's initContainers), mounted at $3.
# $4 is "true" for a read-only claim.
shell_pod() { # ordinal name mountpath readonly
  local ord=$1 name=$2 mnt=$3 ro=$4 node nodefrag image
  node=$(node_of "$ord")
  nodefrag=""
  if [ -n "$node" ]; then nodefrag="\"nodeName\":\"$node\","; fi
  image=$(sts_field '{.spec.template.spec.initContainers[0].image}')
  started+=("$name")
  K apply -f - >/dev/null <<JSON
{"apiVersion":"v1","kind":"Pod","metadata":{"name":"$name","labels":{"app.kubernetes.io/name":"port49-oneshot"}},
 "spec":{"restartPolicy":"Never",${nodefrag}"automountServiceAccountToken":false,
  "volumes":[{"name":"v","persistentVolumeClaim":{"claimName":"data-$sts-$ord","readOnly":$ro}}],
  "containers":[{"name":"sh","image":"$image","command":["sleep","3600"],
    "securityContext":{"runAsUser":0,"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"],"add":["CHOWN","FOWNER","DAC_OVERRIDE"]}},
    "volumeMounts":[{"name":"v","mountPath":"$mnt","readOnly":$ro}]}]}}
JSON
  K wait --for=condition=Ready "pod/$name" --timeout=180s >/dev/null
}

# Waits for a one-shot pod to finish, prints its log, and succeeds only if it did.
finish() { # name
  local phase="" _
  for _ in $(seq 1 180); do
    phase=$(K get pod "$1" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    case $phase in Succeeded | Failed) break ;; esac
    sleep 2
  done
  K logs "$1" -c run || true
  [ "$phase" = Succeeded ]
}
