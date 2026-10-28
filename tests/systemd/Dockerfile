# The systemd smoke's host (plan 12b, Task 9): a Debian trixie with systemd as PID 1 and etcd's
# binaries, standing in for a host that runs the port49-server package. UNVERIFIED: this image has not
# been built. The .deb and the PKI are copied in at run time (docker cp), never baked, so nothing
# secret is in a layer. debian:trixie-slim is pinned by the digest this machine already holds.
FROM debian:trixie-slim@sha256:89c1ea91e897f0fe0a3731595330bc45b8bdef4047464a07116f891a94054b31

RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv dbus ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=gcr.io/etcd-development/etcd:v3.6.15@sha256:5ed4e32061aa061f970d6500629213e8579ef17571dcf9789074966acb9afad1 /usr/local/bin/etcd /usr/local/bin/etcdctl /usr/local/bin/

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
