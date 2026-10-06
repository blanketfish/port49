# OpenLDAP for plan 7g's lab (L42, L43): Debian's slapd, configured by
# cn=config LDIF at first start, with the memberof overlay, TLS from the
# lab PKI, and EXTERNAL mapping the broker's certificate to its account.
FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      slapd ldap-utils ca-certificates && rm -rf /var/lib/apt/lists/*
COPY config.ldif seed.ldif entrypoint.sh /lab/
RUN chmod 0755 /lab/entrypoint.sh
EXPOSE 389 636
ENTRYPOINT ["/lab/entrypoint.sh"]
