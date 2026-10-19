#!/bin/sh
# The compose stack's setup (plan 7f, Task 1), as root, at every `up`.
# Each component's volume gets its own files and nothing else (plan 7e,
# Ruling 1: no host holds both etcd identities):
#   - public files 0644 and directories 0755, owned by root;
#   - a private key 0600, owned by uid 65532, which every port49 process and
#     etcd runs as (keyfile: owner-only; the write fence: a file and its
#     directory owned by the process's user or root, never group- or
#     world-writable);
#   - etcd's root key 0600 root, in a volume only etcd-init mounts.
# It also runs port49d store-roles on a staged copy of both components'
# files and leaves the output for etcd-init.
set -eu
C=/src/config L=/src/local U=65532
pub() { install -o 0 -g 0 -m 0644 "$1" "$2"; }
key() { install -o "$U" -g "$U" -m 0600 "$1" "$2"; }
dir() { install -d -o 0 -g 0 -m 0755 "$@"; }

dir /vol/port49d-etc/etcd
pub "$C/port49d.yaml" /vol/port49d-etc/port49d.yaml
pub "$C/policy.yaml" /vol/port49d-etc/policy.yaml
pub "$C/inventory.yaml" /vol/port49d-etc/inventory.yaml
pub "$L/etcd/ca.pem" /vol/port49d-etc/etcd/ca.pem
pub "$L/etcd/port49d.pem" /vol/port49d-etc/etcd/port49d.pem
key "$L/etcd/port49d-key.pem" /vol/port49d-etc/etcd/port49d-key.pem

dir /vol/broker-etc/etcd /vol/broker-etc/broker
pub "$C/port49-broker.yaml" /vol/broker-etc/port49-broker.yaml
pub "$C/policy.yaml" /vol/broker-etc/policy.yaml
pub "$C/inventory.yaml" /vol/broker-etc/inventory.yaml
pub "$L/etcd/ca.pem" /vol/broker-etc/etcd/ca.pem
pub "$L/etcd/port49-broker.pem" /vol/broker-etc/etcd/port49-broker.pem
key "$L/etcd/port49-broker-key.pem" /vol/broker-etc/etcd/port49-broker-key.pem
pub "$L/broker/broker-ca.pem" /vol/broker-etc/broker/broker-ca.pem
pub "$L/broker/broker.pem" /vol/broker-etc/broker/broker.pem
key "$L/broker/broker-key.pem" /vol/broker-etc/broker/broker-key.pem

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
# and is emptied on every exit
# (Ruling 1 holds inside the project). Nothing after setup needs it: etcd-init
# reads roles.sh from the etcd-root volume.
trap 'rm -rf /etc/port49/*' EXIT
dir /etc/port49/etcd
cp /vol/port49d-etc/port49d.yaml /vol/broker-etc/port49-broker.yaml /etc/port49/
cp /vol/port49d-etc/etcd/* /vol/broker-etc/etcd/* /etc/port49/etcd/
port49d store-roles --config /etc/port49/port49d.yaml --broker-config /etc/port49/port49-broker.yaml \
  > /vol/etcd-root/roles.sh
echo "setup: the component volumes are written; store-roles staged for etcd-init"
