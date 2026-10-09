# L50 (review I-3): what the delegated administrator, user, can do to get round
# the prescribed deny of write on attribute. Every step but "show" and
# "cleanup" is run as user over LDAP to this DC with password, through an AD
# drive that carries the credential, and answers whether the directory accepted
# it, or the refusal's exception type and message (a refusal is a result, not a
# thrown error, so its key is never "error"). Never echoes the password.
#   show     the SDDL of dn (as the script's own account)
#   allow    user adds an explicit allow of WriteProperty on attribute, for itself, to dn
#   own      user takes ownership of dn
#   create   user creates the user entry name in OU=Workloads
#   cleanup  as the script's own account: removes user's explicit allow of
#            WriteProperty on attribute from dn, makes Domain Admins its owner
#            again, deletes the entry name if it exists; answers dn's SDDL
param([string]$step, [string]$dn, [string]$attribute, [string]$user, [string]$password, [string]$name)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$domain = Get-ADDomain
$nb = $domain.NetBIOSName
$ou = "OU=Workloads,$($domain.DistinguishedName)"
$schema = (Get-ADRootDSE).schemaNamingContext
if ($step -eq 'show') {
  @{ sddl = (Get-Acl -Path "AD:$dn").Sddl }
}
elseif ($step -eq 'cleanup') {
  $attrGuid = [guid](Get-ADObject -SearchBase $schema -LDAPFilter "(lDAPDisplayName=$attribute)" -Properties schemaIDGUID).schemaIDGUID
  $sid = (Get-ADUser $user).SID
  $acl = Get-Acl -Path "AD:$dn"
  $mine = @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) | Where-Object {
    $_.AccessControlType -eq 'Allow' -and $_.ActiveDirectoryRights -eq 'WriteProperty' -and
    $_.ObjectType -eq $attrGuid -and $_.IdentityReference.Value -eq $sid.Value })
  foreach ($r in $mine) { $acl.RemoveAccessRuleSpecific($r) }
  $acl.SetOwner((Get-ADGroup 'Domain Admins').SID)
  Set-Acl -Path "AD:$dn" -AclObject $acl
  if (Get-ADUser -Filter "sAMAccountName -eq '$name'") { Remove-ADUser -Identity $name -Confirm:$false }
  @{ removed_aces = $mine.Count; sddl = (Get-Acl -Path "AD:$dn").Sddl }
}
else {
  $cred = New-Object System.Management.Automation.PSCredential("$nb\$user", (ConvertTo-SecureString $password -AsPlainText -Force))
  $sid = (Get-ADUser $user).SID
  try {
    if ($step -eq 'create') {
      New-ADUser -Name $name -SamAccountName $name -Path $ou -Server localhost -Credential $cred
      $made = (Get-ADUser $name).DistinguishedName
      @{ accepted = $true; dn = $made; sddl = (Get-Acl -Path "AD:$made").Sddl }
    } else {
      New-PSDrive -Name L50 -PSProvider ActiveDirectory -Root '//RootDSE/' -Server localhost -Credential $cred | Out-Null
      $acl = Get-Acl -Path "L50:\$dn"
      if ($step -eq 'allow') {
        $attrGuid = [guid](Get-ADObject -SearchBase $schema -LDAPFilter "(lDAPDisplayName=$attribute)" -Properties schemaIDGUID).schemaIDGUID
        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, 'WriteProperty', 'Allow', $attrGuid)))
      } else {
        $acl.SetOwner($sid)
      }
      Set-Acl -Path "L50:\$dn" -AclObject $acl
      @{ accepted = $true; sddl = (Get-Acl -Path "AD:$dn").Sddl }
    }
  } catch {
    @{ accepted = $false; refused_type = $_.Exception.GetType().FullName; refused = "$($_.Exception.Message)" }
  }
  if (Get-PSDrive -Name L50 -ErrorAction SilentlyContinue) { Remove-PSDrive -Name L50 }
}
