# L44: what the note records about the DC: the build, its updates, the domain's
# modes, and every setting a cell depends on, as in force now.
param()
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$os = Get-CimInstance Win32_OperatingSystem
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
function Get-Reg([string]$path, [string]$name) {
  $v = (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name
  if ($null -eq $v) { 'absent' } else { "$v" }
}
$ldap = @{}
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters').psobject.Properties |
  Where-Object Name -like 'ldap*' | ForEach-Object { $ldap[$_.Name] = "$($_.Value)" }
@{
  caption = $os.Caption; version = $os.Version; build = "$($cv.CurrentBuildNumber).$($cv.UBR)"
  display_version = "$($cv.DisplayVersion)"; edition = "$($cv.EditionID)"
  hotfixes = @(Get-HotFix | ForEach-Object { $_.HotFixID })
  domain_mode = "$((Get-ADDomain).DomainMode)"; forest_mode = "$((Get-ADForest).ForestMode)"
  utc_now = [DateTime]::UtcNow.ToString('o')
  strong_certificate_binding_enforcement = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' 'StrongCertificateBindingEnforcement'
  certificate_backdating_compensation = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' 'CertificateBackdatingCompensation'
  certificate_mapping_methods = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel' 'CertificateMappingMethods'
  ntds_ldap_settings = $ldap
  lockout_threshold = (Get-ADDefaultDomainPasswordPolicy).LockoutThreshold
}
