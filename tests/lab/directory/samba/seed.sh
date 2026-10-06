#!/bin/sh
# The directory fixture (plan 7g, Task 17), the same shape as OpenLDAP's, made
# offline against the DC's own database with samba-tool. Passwords are random
# and are used by nothing but the account that holds them, except port49's.
set -eu
BASE=DC=corp,DC=example,DC=com
DB=/var/lib/samba/private/sam.ldb

# A password that meets the domain's complexity rule, random per account.
pw() { printf 'Aa1!%s' "$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"; }

for ou in Staff Contractors G Users-Can-Create Svc; do
  samba-tool ou create "OU=$ou,$BASE" >/dev/null
done

# user <name> <ou> <mail>
user() {
  samba-tool user create "$1" "$(pw)" --userou="OU=$2" --use-username-as-cn --mail-address="$3" >/dev/null
}
user alice Staff alice@corp.example.com
user carol Staff carol@corp.example.com
user dave Staff dave@corp.example.com
user bob Staff bob@corp.example.com
user eve Staff eve@corp.example.com
user eve2 Contractors eve@corp.example.com
samba-tool user create port49 "$LAB_PORT49_PASSWORD" --userou=OU=Svc --use-username-as-cn >/dev/null

group() { samba-tool group add "$1" --groupou="OU=$2" >/dev/null; }
group g-leaf G
group g-mid G
group netops-oncall G
group g-loop-a G
group g-loop-b G
samba-tool group addmembers g-leaf alice >/dev/null
samba-tool group addmembers g-mid g-leaf >/dev/null
samba-tool group addmembers netops-oncall carol,g-mid >/dev/null
samba-tool group addmembers g-loop-a dave,g-loop-b >/dev/null
samba-tool group addmembers g-loop-b g-loop-a >/dev/null

# The second netops-oncall. sAMAccountName is unique domain-wide in AD, so it
# is made under another name and its CN renamed to the same: two groups with
# one cn, as a user with create rights over an OU could make.
group netops-oncall-uc Users-Can-Create
ldbrename -H "$DB" "CN=netops-oncall-uc,OU=Users-Can-Create,$BASE" "CN=netops-oncall,OU=Users-Can-Create,$BASE" >/dev/null

# Alice's strong mapping, computed by the lab test with directory.ADIssuerSerial
# so that port49's form is what the directory holds.
/lab/set-attr.sh "CN=alice,OU=Staff,$BASE" altSecurityIdentities "$LAB_ALICE_ALTSECID"

# The ldap/localhost SPN: port49 binds GSSAPI to ldap/<the URI's host>, and the
# lab's URI host is localhost, which the test certificate names.
samba-tool spn add ldap/localhost 'DC1$' >/dev/null

rm -f /out/port49.keytab
samba-tool domain exportkeytab /out/port49.keytab --principal=port49@CORP.EXAMPLE.COM >/dev/null
chown "$LAB_UID:$LAB_GID" /out/port49.keytab
chmod 0600 /out/port49.keytab
samba-tool user show alice --attributes=objectSid | grep -i '^objectSid' | sed 's/^/lab: alice /'
echo "lab: samba fixture loaded"
