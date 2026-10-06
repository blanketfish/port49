#!/bin/sh
# Build slapd's configuration from /lab/config.ldif, start slapd, load the
# fixture through the overlay, and stay in the foreground. The broker's
# password arrives as LAB_LDAP_PASSWORD and is stored hashed; nothing here
# prints it.
set -eu

install -d -o openldap -g openldap -m 0750 /etc/ldap/tls
for f in server.pem server-key.pem ca.pem; do
  install -o openldap -g openldap -m 0640 "/pki/$f" "/etc/ldap/tls/$f"
done

rm -rf /etc/ldap/slapd.d /var/lib/ldap
install -d -o openldap -g openldap -m 0750 /etc/ldap/slapd.d /var/lib/ldap /run/slapd
slapadd -n0 -F /etc/ldap/slapd.d -l /lab/config.ldif
chown -R openldap:openldap /etc/ldap/slapd.d /var/lib/ldap

hash=$(slappasswd -h '{SSHA}' -s "$LAB_LDAP_PASSWORD")
sed "s|@PORT49_PASSWORD_HASH@|$hash|" /lab/seed.ldif > /tmp/seed.ldif
unset hash LAB_LDAP_PASSWORD

slapd -d 256 -F /etc/ldap/slapd.d -h "ldap:/// ldaps:/// ldapi:///" -u openldap -g openldap &
pid=$!
trap 'kill $pid 2>/dev/null' TERM INT

i=0
until ldapsearch -Y EXTERNAL -H ldapi:/// -b '' -s base -LLL namingContexts >/dev/null 2>&1; do
  i=$((i + 1))
  [ "$i" -lt 60 ] || { echo "lab: slapd never answered on ldapi" >&2; exit 1; }
  sleep 0.5
done
ldapadd -Y EXTERNAL -H ldapi:/// -f /tmp/seed.ldif >/dev/null
rm -f /tmp/seed.ldif
# The end-to-end lab (plan 7g, Task 18) changes group membership while the
# directory runs, and ldapi is closed once tls=1 is set: with LAB_OPENLDAP_WRITER
# set, one account may write over LDAPS, bound with LAB_ADMIN_PASSWORD (a random
# value no other lab reads). L42 and L43 never set it.
if [ -n "${LAB_OPENLDAP_WRITER:-}" ]; then
  whash=$(slappasswd -h '{SSHA}' -s "$LAB_ADMIN_PASSWORD")
  ldapadd -Y EXTERNAL -H ldapi:/// >/dev/null <<LDIF
dn: cn=lab-writer,ou=Svc,dc=corp,dc=example,dc=com
objectClass: inetOrgPerson
cn: lab-writer
sn: lab-writer
userPassword: $whash
LDIF
  unset whash
  ldapmodify -Y EXTERNAL -H ldapi:/// >/dev/null <<'LDIF'
dn: olcDatabase={1}mdb,cn=config
changetype: modify
delete: olcAccess
olcAccess: {2}
-
add: olcAccess
olcAccess: {2}to * by dn.exact="cn=lab-writer,ou=Svc,dc=corp,dc=example,dc=com" write by dn.exact="cn=port49,ou=Svc,dc=corp,dc=example,dc=com" read by * none
LDIF
fi
# From here on every operation must be under TLS: a simple bind over plain LDAP
# is refused, and so is anything over ldapi, which nothing later uses.
ldapmodify -Y EXTERNAL -H ldapi:/// >/dev/null <<'LDIF'
dn: cn=config
changetype: modify
replace: olcSecurity
olcSecurity: tls=1
LDIF
echo "lab: openldap fixture loaded"
wait $pid
