# The systemd smoke's host (plan 12b, Task 9): a Debian trixie with systemd as PID 1 and etcd's
# binaries, standing in for a host that runs the port49-server package. UNVERIFIED: this image has not
# been built. The .deb and the PKI are copied in at run time (docker cp), never baked, so nothing
# secret is in a layer. debian:trixie-slim is pinned by the digest this machine already holds.
# sudo is here so the smoke runs the README's break-glass line as written.
FROM debian:trixie-slim@sha256:89c1ea91e897f0fe0a3731595330bc45b8bdef4047464a07116f891a94054b31

RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv dbus ca-certificates sudo \
 && rm -rf /var/lib/apt/lists/*

COPY --from=gcr.io/etcd-development/etcd:v3.6.15@sha256:5ed4e32061aa061f970d6500629213e8579ef17571dcf9789074966acb9afad1 /usr/local/bin/etcd /usr/local/bin/etcdctl /usr/local/bin/

# The container is not privileged, so Docker mounts its cgroup read-only: with CAP_SYS_ADMIN (the only
# capability the smoke adds) the init makes its own cgroup mount writable, and says so if it cannot.
STOPSIGNAL SIGRTMIN+3
CMD ["/bin/sh", "-c", "mount -o remount,rw /sys/fs/cgroup || echo 'port49-systemd: /sys/fs/cgroup stays read-only' >&2; exec /sbin/init"]
