#!/bin/sh
# l50-seed.sh <password> [acl set|clear <attribute> | sddl | dacl allow|create|delete|get ...]:
# L50's writers on Samba AD, as l50_seed.ps1 makes them on Windows. The
# password is read from $1 and never printed.
# - "acl set <attribute>" writes the prescribed deny of write on <attribute> on
#   OU=Workloads for SELF, Account Operators and l50-ouadmin, then prints the
#   OU's and the target's security descriptors (the evidence the ACEs landed).
# - "acl clear <attribute>" re-seeds the OU (Samba 4.17 has no dsacl delete),
#   which also recreates the target, then prints the same descriptors.
# - "sddl" prints those descriptors: the evidence of what the "default" cells
#   ran under (pre-flight I-8).
# - "dacl ..." acts as the delegated admin l50-ouadmin, not as root: "allow
#   <attribute>" adds an explicit allow of write on <attribute> for itself to
#   the target; "create" makes the user l50-made in the OU; "delete" removes it;
#   "get <cn>" prints the descriptor of CN=<cn> in the OU.
set -eu
pw=$1
sam=/var/lib/samba/private/sam.ldb
base=$(ldbsearch -H $sam -s base -b "" defaultNamingContext | sed -n 's/^defaultNamingContext: //p')
ou="OU=Workloads,$base"
target="CN=svc-oxidized-01,$ou"
if [ "${2:-}" = sddl ]; then
  samba-tool dsacl get --objectdn="$ou"
  samba-tool dsacl get --objectdn="$target"
  exit 0
fi
if [ "${2:-}" = acl ] && [ "$3" = clear ]; then
  # Samba 4.17's samba-tool has no "dsacl delete" (it came after): clear the
  # prescribed denies by re-seeding the OU, which also recreates the target.
  samba-tool ou delete "$ou" --force-subtree-delete >/dev/null
  "$0" "$pw"
  exec "$0" "$pw" sddl
fi
# schemaid prints the schemaIDGUID of the attribute $1. --show-binary prints it
# as a dashed GUID; anything else (empty, or base64 from a "schemaIDGUID::"
# line) would make an ACE with no object GUID, a deny of every property: fail
# loudly instead (pre-flight M-7).
schemaid() {
  guid=$(ldbsearch -H $sam --show-binary -b "CN=Schema,CN=Configuration,$base" "(lDAPDisplayName=$1)" schemaIDGUID |
    sed -n 's/^schemaIDGUID: //p')
  case "$guid" in
    ????????-????-????-????-????????????) echo "$guid" ;;
    *) echo "l50-seed.sh: no schemaIDGUID for $1 (read '$guid'); no ACE written" >&2; exit 2 ;;
  esac
}
# ouadminsid prints the objectSid of l50-ouadmin.
ouadminsid() {
  s=$(samba-tool user show l50-ouadmin --attributes=objectSid | sed -n 's/^objectSid: //p')
  case "$s" in
    S-1-5-21-*) echo "$s" ;;
    *) echo "l50-seed.sh: no objectSid for l50-ouadmin (read '$s'); no ACE written" >&2; exit 2 ;;
  esac
}
if [ "${2:-}" = acl ]; then
  guid=$(schemaid "$4")
  ouadmin=$(ouadminsid)
  for sid in PS AO "$ouadmin"; do
    ace="(OD;CI;WP;$guid;bf967aba-0de6-11d0-a285-00aa003049e2;$sid)"
    samba-tool dsacl set --objectdn="$ou" --sddl="$ace" >/dev/null
  done
  exec "$0" "$pw" sddl
fi
if [ "${2:-}" = dacl ]; then
  # Every one of these is a bind by l50-ouadmin over ldap://localhost (NTLM
  # with signing; the DC requires strong auth), so the directory decides.
  case "$3" in
    allow)
      ace="(OA;;WP;$(schemaid "$4");;$(ouadminsid))"
      samba-tool dsacl set --objectdn="$target" --sddl="$ace" -H ldap://localhost -U "l50-ouadmin%$pw" >/dev/null
      ;;
    create)
      samba-tool user create l50-made "$pw" --userou=OU=Workloads -H ldap://localhost -U "l50-ouadmin%$pw" >/dev/null
      ;;
    delete) samba-tool user delete l50-made >/dev/null ;;
    get) samba-tool dsacl get --objectdn="CN=$4,$ou" ;;
    *) echo "l50-seed.sh: dacl $3?" >&2; exit 2 ;;
  esac
  exit 0
fi
samba-tool ou create "$ou" >/dev/null 2>&1 || true
for u in svc-oxidized-01 l50-acctop l50-ouadmin l50-user; do
  path=CN=Users
  [ "$u" = svc-oxidized-01 ] && path=OU=Workloads
  samba-tool user create "$u" "$pw" --userou="$path" >/dev/null 2>&1 || samba-tool user setpassword "$u" --newpassword="$pw" >/dev/null
done
samba-tool group addmembers "Account Operators" l50-acctop >/dev/null 2>&1 || true
sid=$(samba-tool user show l50-ouadmin --attributes=objectSid | sed -n 's/^objectSid: //p')
# The wizard's ACEs: create and delete user objects; full control over them.
samba-tool dsacl set --objectdn="$ou" --sddl="(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;$sid)" >/dev/null
samba-tool dsacl set --objectdn="$ou" --sddl="(A;CIIO;GA;;bf967aba-0de6-11d0-a285-00aa003049e2;$sid)" >/dev/null
