#!/bin/sh
# Applies port49's etcd roles and enables auth, once (plan 7f, Task 1), as
# etcd's root. A later run finds auth enabled and changes nothing: roles
# changed by a port49 upgrade are re-applied by hand from store-roles'
# output (plan 7e's notes), never silently here.
set -eu
export ETCDCTL_ENDPOINTS=https://etcd-1:2379,https://etcd-2:2379,https://etcd-3:2379
export ETCDCTL_CACERT=/etcd-root/ca.pem ETCDCTL_CERT=/etcd-root/root.pem ETCDCTL_KEY=/etcd-root/root-key.pem
i=0
until etcdctl endpoint health >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge 120 ]; then
    echo "etcd-init: the three members did not all answer in 120s" >&2
    etcdctl endpoint health >&2 || true
    exit 1
  fi
  sleep 1
done
if etcdctl auth status 2>/dev/null | grep -q 'Authentication Status: true'; then
  echo "etcd-init: auth is already enabled; the roles stand as applied"
  exit 0
fi
# Each line of roles.sh is one etcdctl command. A run that stopped partway
# (an etcd restart, a killed container) left some of them applied, and `role
# add` and `user add` fail on a name that exists: tolerate exactly that, so
# the next `up` finishes the job instead of failing under `set -e`.
apply() {
  if out=$("$@" 2>&1); then
    return 0
  fi
  case "$out" in
    *"already exists"*) return 0 ;;
  esac
  echo "etcd-init: $* failed: $out" >&2
  exit 1
}
while IFS= read -r line; do
  case "$line" in
    "" | "#"*) continue ;;
  esac
  # shellcheck disable=SC2086 # one etcdctl command per line, split on spaces
  apply $line
done < /etcd-root/roles.sh
apply etcdctl user add root --no-password
apply etcdctl user grant-role root root
etcdctl auth enable
echo "etcd-init: port49's roles applied and auth enabled"
