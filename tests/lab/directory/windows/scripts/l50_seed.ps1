# L50: the writers and the target. A service account in OU=Workloads, an
# Account Operators member, a delegated OU administrator (the delegation
# wizard's "Create, delete, and manage user accounts" on OU=Workloads), and an
# ordinary user, every one with actor_password. Idempotent: a re-run resets
# the passwords and the delegation, and removes a previous run's prescribed
# denies, so a reused DC's "default" cells are measured at the default. It
# answers the OU's SDDL after that, the evidence of what "default" was.
param([string]$actor_password)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$domain = Get-ADDomain
$base = $domain.DistinguishedName
$nb = $domain.NetBIOSName
$ou = "OU=Workloads,$base"
if (-not (Get-ADOrganizationalUnit -LDAPFilter '(ou=Workloads)' -SearchBase $base -SearchScope OneLevel)) {
  New-ADOrganizationalUnit -Name Workloads -Path $base -ProtectedFromAccidentalDeletion $false
}
$pw = ConvertTo-SecureString $actor_password -AsPlainText -Force
function Set-Actor([string]$name, [string]$path) {
  if (Get-ADUser -Filter "sAMAccountName -eq '$name'") {
    Set-ADAccountPassword -Identity $name -Reset -NewPassword $pw
    Enable-ADAccount -Identity $name
  } else {
    New-ADUser -Name $name -SamAccountName $name -Path $path -AccountPassword $pw -Enabled $true -PasswordNeverExpires $true
  }
}
Set-Actor 'svc-oxidized-01' $ou
Set-Actor 'l50-acctop' "CN=Users,$base"
Set-Actor 'l50-ouadmin' "CN=Users,$base"
Set-Actor 'l50-user' "CN=Users,$base"
Add-ADGroupMember -Identity 'Account Operators' -Members 'l50-acctop'
# The wizard's ACEs: create and delete user objects, full control over them.
dsacls $ou /G "$nb\l50-ouadmin:CCDC;user" | Out-Null
dsacls $ou /I:S /G "$nb\l50-ouadmin:GA;;user" | Out-Null
# A previous run's prescribed denies (audit.ps1 acl set), and nothing else:
# an explicit deny of WriteProperty on user objects for SELF, Account
# Operators or l50-ouadmin. Never dsacls /R, which strips a trustee's every
# ACE, Account Operators' default grants on the OU included (pre-flight I-8).
$schema = (Get-ADRootDSE).schemaNamingContext
$userClass = [guid](Get-ADObject -SearchBase $schema -LDAPFilter '(lDAPDisplayName=user)' -Properties schemaIDGUID).schemaIDGUID
$sids = @('S-1-5-10', 'S-1-5-32-548', (Get-ADUser 'l50-ouadmin').SID.Value)
$acl = Get-Acl -Path "AD:$ou"
$stale = @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) | Where-Object {
  $_.AccessControlType -eq 'Deny' -and $_.ActiveDirectoryRights -eq 'WriteProperty' -and
  $_.InheritedObjectType -eq $userClass -and $sids -contains $_.IdentityReference.Value })
foreach ($r in $stale) { $acl.RemoveAccessRuleSpecific($r) }
if ($stale.Count -gt 0) { Set-Acl -Path "AD:$ou" -AclObject $acl }
$sddl = (Get-Acl -Path "AD:$ou").Sddl
@{ ou = $ou; target = (Get-ADUser 'svc-oxidized-01').DistinguishedName; removed_denies = $stale.Count
   sddl = $sddl.Substring(0, [Math]::Min(4000, $sddl.Length)) }
