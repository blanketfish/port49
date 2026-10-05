#!/bin/sh
# Provision the domain on first start, seed the fixture, and run the DC in
# the foreground. The administrator's password arrives as LAB_ADMIN_PASSWORD
# and the broker's as LAB_PORT49_PASSWORD; nothing here prints either.
set -eu

DB=/var/lib/samba/private/sam.ldb

if [ ! -e "$DB" ]; then
  rm -f /etc/samba/smb.conf
  # The sysvol ACLs are kept in user.NTACL: a container may not write the
  # default security.NTACL xattr, and nothing in this lab reads sysvol.
  samba-tool domain provision --realm=CORP.EXAMPLE.COM --domain=CORP --server-role=dc \
    --dns-backend=SAMBA_INTERNAL --adminpass="$LAB_ADMIN_PASSWORD" \
    --option="acl_xattr:security_acl_name = user.NTACL" >/dev/null

  install -d -m 0700 /var/lib/samba/private/lab-tls
  for f in server.pem server-key.pem ca.pem; do
    install -m 0600 "/pki/$f" "/var/lib/samba/private/lab-tls/$f"
  done
  # smb.conf is written by provision with a single [global] and the DC's
  # [sysvol] and [netlogon]: the options go straight under [global].
  sed -i '/^\[global\]/a \
\ttls enabled = yes\
\ttls certfile = /var/lib/samba/private/lab-tls/server.pem\
\ttls keyfile = /var/lib/samba/private/lab-tls/server-key.pem\
\ttls cafile = /var/lib/samba/private/lab-tls/ca.pem\
\tldap server require strong auth = yes\
\tacl_xattr:security_acl_name = user.NTACL\
\tlog level = 1' /etc/samba/smb.conf

  /lab/seed.sh
fi

exec samba -i
