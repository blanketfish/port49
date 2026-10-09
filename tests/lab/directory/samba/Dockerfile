# Samba 4 as an Active Directory DC for plan 7g's lab: Debian's samba,
# provisioned at first start, the fixture made with samba-tool, and the
# broker's keytab exported for GSSAPI.
FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      samba samba-ad-provision samba-dsdb-modules samba-vfs-modules krb5-user winbind ldb-tools ca-certificates && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh seed.sh set-attr.sh l50-seed.sh /lab/
RUN chmod 0755 /lab/entrypoint.sh /lab/seed.sh /lab/set-attr.sh /lab/l50-seed.sh
EXPOSE 88/tcp 88/udp 389 636
ENTRYPOINT ["/lab/entrypoint.sh"]
