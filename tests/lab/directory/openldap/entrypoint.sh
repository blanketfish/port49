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

# The end-to-end lab restarts this container to end a directory outage, and the
# directory it brings back is the same one: a reloaded fixture gives every entry
# a new entryUUID, which port49 correctly refuses (a principal is pinned to its
# entry, Ruling 3). With LAB_OPENLDAP_WRITER set and a database already seeded,
# the configuration and data stay as they were. L42 and L43 never set it.
if [ -n "${LAB_OPENLDAP_WRITER:-}" ] && [ -e /var/lib/ldap/.seeded ]; then
  echo "lab: openldap fixture loaded (kept from the first start; every entryUUID is unchanged)"
  exec slapd -d 256 -F /etc/ldap/slapd.d -h "ldap:/// ldaps:/// ldapi:///" -u openldap -g openldap
fi

rm -rf /etc/ldap/slapd.d /var/lib/ldap
install -d -o openldap -g openldap -m 0750 /etc/ldap/slapd.d /var/lib/ldap /run/slapd
slapadd -n0 -F /etc/ldap/slapd.d -l /lab/config.ldif
chown -R openldap:openldap /etc/ldap/slapd.d /var/lib/ldap

hash=$(slappasswd -h '{SSHA}' -s "$LAB_LDAP_PASSWORD")
# L67 (plan 9e): the people's password, the run's when LAB_L67_PASSWORD is set
# and a random one otherwise, hashed as the broker's is. It is never printed.
person=${LAB_L67_PASSWORD:-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')}
phash=$(slappasswd -h '{SSHA}' -s "$person")
sed -e "s|@PORT49_PASSWORD_HASH@|$hash|" -e "s|@PERSON_PASSWORD_HASH@|$phash|" /lab/seed.ldif > /tmp/seed.ldif
unset hash person LAB_LDAP_PASSWORD LAB_L67_PASSWORD

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
# L67: the people's passwords and four more people, loaded before the ppolicy
# overlay exists (so nothing the overlay owns is set by an add, pwdReset
# included), then the overlay, then each person put in the state a bind is
# asked about, as the root DN. The fourth, l67-locked, is locked by the test
# with failed binds. Nothing here runs without LAB_L67, so L42, L43 and the
# end-to-end lab keep the fixture they were measured on.
if [ -n "${LAB_L67:-}" ]; then
  ldapmodify -Y EXTERNAL -H ldapi:/// -f /lab/ppolicy-module.ldif >/dev/null
  sed "s|@PERSON_PASSWORD_HASH@|$phash|" /lab/l67.ldif > /tmp/l67.ldif
  ldapmodify -a -Y EXTERNAL -H ldapi:/// -f /tmp/l67.ldif >/dev/null
  rm -f /tmp/l67.ldif
  ldapmodify -Y EXTERNAL -H ldapi:/// -f /lab/ppolicy.ldif >/dev/null
  # -e relax: these are no-user-modification attributes, which only the
  # relax rules control lets the root DN write.
  ldapmodify -e relax -Y EXTERNAL -H ldapi:/// >/dev/null <<'LDIF'
dn: uid=l67-expired,ou=Staff,dc=corp,dc=example,dc=com
changetype: modify
replace: pwdChangedTime
pwdChangedTime: 20200101000000Z

dn: uid=l67-disabled,ou=Staff,dc=corp,dc=example,dc=com
changetype: modify
replace: pwdAccountLockedTime
pwdAccountLockedTime: 000001010000Z

dn: uid=l67-mustchange,ou=Staff,dc=corp,dc=example,dc=com
changetype: modify
replace: pwdReset
pwdReset: TRUE
LDIF
fi
unset phash
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
# L67 keeps ldapi usable by asking for a security strength (ssf=56) that TLS and
# the local socket (SSF 71) meet and a plain LDAP connection does not: the test
# flips olcPPolicyUseLockout over ldapi during cell (c), which tls=1 would refuse.
if [ -n "${LAB_L67:-}" ]; then
  ldapmodify -Y EXTERNAL -H ldapi:/// >/dev/null <<'LDIF'
dn: cn=config
changetype: modify
replace: olcSecurity
olcSecurity: ssf=56
LDIF
else
  ldapmodify -Y EXTERNAL -H ldapi:/// >/dev/null <<'LDIF'
dn: cn=config
changetype: modify
replace: olcSecurity
olcSecurity: tls=1
LDIF
fi
[ -z "${LAB_OPENLDAP_WRITER:-}" ] || touch /var/lib/ldap/.seeded
echo "lab: openldap fixture loaded"
wait $pid
