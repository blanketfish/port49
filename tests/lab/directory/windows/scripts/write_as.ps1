# L50: one write of one attribute on one entry, bound as user with password,
# over LDAP to this DC. Answers written (and whether the value reads back),
# or refused with the exception's type and message. Never echoes the password.
# A refusal is a result, not a thrown error, so its key is never "error".
param([string]$dn, [string]$attribute, [string]$value, [string]$user, [string]$password)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$nb = (Get-ADDomain).NetBIOSName
$cred = New-Object System.Management.Automation.PSCredential("$nb\$user", (ConvertTo-SecureString $password -AsPlainText -Force))
try {
  Set-ADObject -Identity $dn -Replace @{ $attribute = $value } -Credential $cred -Server localhost
  $got = (Get-ADObject -Identity $dn -Properties $attribute).$attribute
  @{ written = $true; reads_back = ("$got" -ceq $value) }
} catch {
  @{ written = $false; refused_type = $_.Exception.GetType().FullName; refused = "$($_.Exception.Message)" }
}
