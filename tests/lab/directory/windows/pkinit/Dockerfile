# MIT Kerberos's kinit with the PKINIT plugin (L44): the client that asks the
# Windows DC's KDC for a TGT with a certificate, so the DC's own mapping
# (KB5014754) is what answers. Debian bookworm, pinned by digest.
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      krb5-user krb5-pkinit ca-certificates && rm -rf /var/lib/apt/lists/*
