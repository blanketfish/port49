#!/bin/sh
# The compose stack's setup (plan 7f, Task 1), as root, at every `up`.
# Each component's volume gets its own files and nothing else (plan 7e,
# Ruling 1: no host holds both etcd identities):
#   - public files 0644 and directories 0755, owned by root;
#   - a private key 0600, owned by uid 65532, which every port49 process and
#     etcd runs as (keyfile: owner-only; the write fence: a file and its
#     directory owned by the process's user or root, never group- or
#     world-writable);
#   - a secret is a file, never an environment variable (spec decision 54
#     ruling 2): the device keys in the port49d-keys volume, root:65532 0750
#     with each file 0440, mounted read-only at /run/port49/keys; each
#     component's sealing key in its own -etc volume under secrets/, 65532 0400;
#   - etcd's root key 0600 root, in a volume only etcd-init mounts.
# It also runs port49d store-roles on a staged copy of both components'
# files and leaves the output for etcd-init.
set -eu
C=/src/config L=/src/local U=65532
pub() { install -o 0 -g 0 -m 0644 "$1" "$2"; }
key() { install -o "$U" -g "$U" -m 0600 "$1" "$2"; }
dir() { install -d -o 0 -g 0 -m 0755 "$@"; }

# A key is placed once and never replaced in place: a device holds the key it was
# given, and a sealing key re-written would strand what it sealed. At every `up`:
# absent in the volume: installed; the same bytes: left alone; different bytes:
# refused (the stack stops, the volume untouched); gone from local/: the
# installed one is kept and the line says so. The copy is a temp file in the
# destination directory, linked in without clobbering, so no step overwrites.
TMP=
trap 'rm -f "$TMP"; rm -rf /etc/port49/*' EXIT
once() { # source, destination, owner, group, mode
  if [ ! -e "$1" ]; then
    [ -e "$2" ] || { echo "setup: $1 is missing and $2 is not installed" >&2; exit 1; }
    echo "setup: $1 is gone; keeping the installed $2"
    return 0
  fi
  if [ -e "$2" ]; then
    cmp -s "$1" "$2" && return 0
    echo "setup: refusing: $2 differs from $1; keys are never replaced in place (add a new version file)" >&2
    exit 1
  fi
  TMP=$(mktemp "$(dirname "$2")/.once.XXXXXX")
  install -o "$3" -g "$4" -m "$5" "$1" "$TMP"
  ln "$TMP" "$2"
  rm -f "$TMP"
  TMP=
}

dir /vol/port49d-etc/etcd /vol/port49d-etc/secrets
pub "$C/port49d.yaml" /vol/port49d-etc/port49d.yaml
pub "$C/policy.yaml" /vol/port49d-etc/policy.yaml
pub "$C/inventory.yaml" /vol/port49d-etc/inventory.yaml
pub "$L/etcd/ca.pem" /vol/port49d-etc/etcd/ca.pem
pub "$L/etcd/port49d.pem" /vol/port49d-etc/etcd/port49d.pem
key "$L/etcd/port49d-key.pem" /vol/port49d-etc/etcd/port49d-key.pem
once "$L/secrets/port49d-encryption.key" /vol/port49d-etc/secrets/encryption.key "$U" "$U" 0400

# The device keys: one file per version, never rewritten once a device holds
# it. A new version is a new file written here and named in the policy.
install -d -o 0 -g "$U" -m 0750 /vol/port49d-keys
for k in "$L"/keys/*; do
  [ -e "$k" ] || continue
  once "$k" "/vol/port49d-keys/$(basename "$k")" 0 "$U" 0440
done
for k in /vol/port49d-keys/*; do
  [ -e "$k" ] || continue
  [ -e "$L/keys/$(basename "$k")" ] || echo "setup: $L/keys/$(basename "$k") is gone; keeping the installed $k"
done

dir /vol/broker-etc/etcd /vol/broker-etc/broker /vol/broker-etc/secrets
pub "$C/port49-broker.yaml" /vol/broker-etc/port49-broker.yaml
pub "$C/policy.yaml" /vol/broker-etc/policy.yaml
pub "$C/inventory.yaml" /vol/broker-etc/inventory.yaml
pub "$L/etcd/ca.pem" /vol/broker-etc/etcd/ca.pem
pub "$L/etcd/port49-broker.pem" /vol/broker-etc/etcd/port49-broker.pem
key "$L/etcd/port49-broker-key.pem" /vol/broker-etc/etcd/port49-broker-key.pem
pub "$L/broker/broker-ca.pem" /vol/broker-etc/broker/broker-ca.pem
pub "$L/broker/broker.pem" /vol/broker-etc/broker/broker.pem
key "$L/broker/broker-key.pem" /vol/broker-etc/broker/broker-key.pem
once "$L/secrets/broker-encryption.key" /vol/broker-etc/secrets/encryption.key "$U" "$U" 0400
# The roots an admin operation's touch is checked against, when a deployment
# names them (README, "Admin operations").
[ ! -f "$L/broker/attestation-roots.pem" ] || pub "$L/broker/attestation-roots.pem" /vol/broker-etc/broker/attestation-roots.pem

dir /vol/etcd-pki
pub "$L/etcd/ca.pem" /vol/etcd-pki/ca.pem
for m in etcd-1 etcd-2 etcd-3; do
  pub "$L/etcd/$m.pem" "/vol/etcd-pki/$m.pem"
  key "$L/etcd/$m-key.pem" "/vol/etcd-pki/$m-key.pem"
  chown "$U:$U" "/vol/$m-data"
  chmod 0700 "/vol/$m-data"
done

install -d -o 0 -g 0 -m 0700 /vol/etcd-root
pub "$L/etcd/ca.pem" /vol/etcd-root/ca.pem
pub "$L/etcd/root.pem" /vol/etcd-root/root.pem
install -o 0 -g 0 -m 0600 "$L/etcd/root-key.pem" /vol/etcd-root/root-key.pem

# store-roles reads both components' stores: blocks and the files they name, at the
# paths each container sees them: stage both here, in this container alone.
# The staged copy holds both components' etcd private keys and the exited
# container keeps its filesystem layer, so /etc/port49 is a tmpfs (compose.yaml)
# and is emptied on every exit (the trap at the top)
# (Ruling 1 holds inside the project). Nothing after setup needs it: etcd-init
# reads roles.sh from the etcd-root volume.
dir /etc/port49/etcd /etc/port49/secrets
cp /vol/port49d-etc/secrets/encryption.key /etc/port49/secrets/encryption.key
cp /vol/port49d-etc/port49d.yaml /vol/broker-etc/port49-broker.yaml /etc/port49/
cp /vol/port49d-etc/etcd/* /vol/broker-etc/etcd/* /etc/port49/etcd/
port49d store-roles --config /etc/port49/port49d.yaml --broker-config /etc/port49/port49-broker.yaml \
  > /vol/etcd-root/roles.sh
echo "setup: the component volumes are written; store-roles staged for etcd-init"
