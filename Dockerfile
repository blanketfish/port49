# syntax=docker/dockerfile:1.7
#
# port49's container image (plan 7f, Task 1): one peer shape beside systemd
# and Kubernetes; nothing in port49 requires it (roadmap, "Deployment
# shapes").
#
#   target port49: the four static binaries on distroless, as uid 65532
#   target setup:  the compose stack's one-shot setup and etcd-init (root,
#                  alpine, etcdctl); never runs port49 itself

# Base images are pinned by digest (the tag is the comment); bump both together.
# The build stage runs on the builder's own architecture and cross-compiles, so
# an arm64 image needs no emulation: nothing after it runs a target binary.
# golang:1.26
FROM --platform=$BUILDPLATFORM golang:1.26@sha256:3e81679b4c293b7eecc6f8a044b355a3062a09db22cca961731c81a2dbcd8f83 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/ \
      ./cmd/port49d ./cmd/port49-broker ./cmd/port49 ./cmd/port49-inventory
# the three 0700 directories, as a tree COPY carries whole (see port49 below)
RUN install -d -m 0700 /out/tree/var/lib/port49-broker /out/tree/var/spool/port49d /out/tree/run/port49
# the base ships /var/local as root:staff 2775, which the layout check refuses (group write)
RUN install -d -m 0755 /out/tree/var/local

# v3.6.15
FROM gcr.io/etcd-development/etcd:v3.6.15@sha256:5ed4e32061aa061f970d6500629213e8579ef17571dcf9789074966acb9afad1 AS etcd

# static-debian12:nonroot
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS port49
COPY --from=build /out/port49d /out/port49-broker /out/port49 /out/port49-inventory /usr/local/bin/
# Each directory a process writes, 0700 and owned by the user it runs as. A
# named volume first mounted on one is created from it, ownership and mode
# included, so broker.state_dir passes port49-broker's check (writable by
# no group or other user; plan 7e, Ruling T15-b) on its first mount and on
# every one after; no fsGroup-like step is needed. Each COPY names the
# parent and so carries the directory itself with its mode: copying a
# directory's contents into a new one gives it 0755 on the classic builder,
# and COPY --chmod needs BuildKit.
COPY --from=build --chown=65532:65532 /out/tree/var/lib/ /var/lib/
COPY --from=build --chown=65532:65532 /out/tree/var/spool/ /var/spool/
COPY --from=build /out/tree/var/local/ /var/local/
COPY --from=build --chown=65532:65532 /out/tree/run/ /run/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/port49d"]

# alpine:3.22
FROM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f AS setup
COPY --from=etcd /usr/local/bin/etcdctl /usr/local/bin/etcdctl
COPY --from=build /out/port49d /usr/local/bin/port49d
COPY deploy/compose/setup.sh deploy/compose/etcd-init.sh /usr/local/bin/
ENTRYPOINT ["/bin/sh"]
