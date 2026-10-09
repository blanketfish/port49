# L50: the audit trail. mode "state" answers the audit settings as found,
# changing none; mode "on" turns Directory Service Changes auditing on
# and puts a success-and-failure SACL for Everyone's writes on OU=Workloads,
# inherited by its objects; "read" answers the Security log's 5136
# (attribute modified) and 4662 (an access) events since a moment, each cut
# at 600 characters; "acl" sets or clears the prescribed deny on attribute.
param([string]$mode, [string]$since, [string]$attribute, [string]$state)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$domain = Get-ADDomain
$nb = $domain.NetBIOSName
$ou = "OU=Workloads,$($domain.DistinguishedName)"
switch ($mode) {
  'state' {
    # Read-only: what auditing is set to now, before "on" changes any of it.
    # On a reused DC this is the previous run's, not the default (re-review N-1).
    $audit = (Get-Acl -Path "AD:$ou" -Audit).GetSecurityDescriptorSddlForm('Audit')
    @{ changes = (auditpol /get /subcategory:"Directory Service Changes" | Out-String).Trim()
       access = (auditpol /get /subcategory:"Directory Service Access" | Out-String).Trim()
       sacl = "$audit" }
  }
  'on' {
    auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable | Out-Null
    $acl = Get-Acl -Path "AD:$ou" -Audit
    $everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($everyone, 'WriteProperty',
      'Success,Failure', [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)
    $acl.AddAuditRule($rule)
    Set-Acl -Path "AD:$ou" -AclObject $acl
    @{ audit = (auditpol /get /subcategory:"Directory Service Changes" | Out-String).Trim() }
  }
  'read' {
    $t = [DateTime]::Parse($since, $null, [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime()
    $evs = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5136, 4662; StartTime = $t } -ErrorAction SilentlyContinue |
      ForEach-Object { $m = "$($_.Message)" -replace '\s+', ' '
        @{ id = $_.Id; time = $_.TimeCreated.ToUniversalTime().ToString('o'); message = $m.Substring(0, [Math]::Min(600, $m.Length)) } })
    @{ events = $evs }
  }
  'acl' {
    # The prescribed ACL under test: an inherited deny of write on attribute,
    # on OU=Workloads, for SELF, Account Operators and the delegated admin.
    # "clear" removes exactly the rules "set" adds, never another ACE: dsacls
    # /R would strip each trustee's every ACE on the OU, Account Operators'
    # default create/delete grants included (pre-flight I-8).
    $schema = (Get-ADRootDSE).schemaNamingContext
    $attrGuid = [guid](Get-ADObject -SearchBase $schema -LDAPFilter "(lDAPDisplayName=$attribute)" -Properties schemaIDGUID).schemaIDGUID
    $userClass = [guid](Get-ADObject -SearchBase $schema -LDAPFilter '(lDAPDisplayName=user)' -Properties schemaIDGUID).schemaIDGUID
    $acl = Get-Acl -Path "AD:$ou"
    foreach ($sid in @('S-1-5-10', 'S-1-5-32-548', (Get-ADUser 'l50-ouadmin').SID.Value)) {
      $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        (New-Object System.Security.Principal.SecurityIdentifier($sid)), 'WriteProperty', 'Deny', $attrGuid,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents, $userClass)
      if ($state -eq 'set') { $acl.AddAccessRule($rule) } else { $acl.RemoveAccessRuleSpecific($rule) }
    }
    Set-Acl -Path "AD:$ou" -AclObject $acl
    $sddl = (Get-Acl -Path "AD:$ou").Sddl
    @{ ou = $ou; state = $state; sddl = $sddl.Substring(0, [Math]::Min(4000, $sddl.Length)) }
  }
}
