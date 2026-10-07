# L44: set (or, with value -1, delete) one of the DC settings the run varies,
# restart the service that reads it, then start again every service that
# depends on it and was running before (Restart-Service -Force stops them all;
# restarting the service guarantees the value is read), and return what is in
# force after.
param([string]$name, [int]$value)
$ErrorActionPreference = 'Stop'
$known = @{
  StrongCertificateBindingEnforcement              = @('HKLM:\SYSTEM\CurrentControlSet\Services\Kdc', 'Kdc')
  UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors = @('HKLM:\SYSTEM\CurrentControlSet\Services\Kdc', 'Kdc')
  LdapEnforceChannelBinding                        = @('HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters', 'NTDS')
}
if (-not $known.ContainsKey($name)) { throw "not a setting this lab varies: $name" }
$path, $svc = $known[$name]
if ($value -lt 0) { Remove-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue }
else { New-ItemProperty -Path $path -Name $name -PropertyType DWord -Value $value -Force | Out-Null }
$running = @(@($svc) + @((Get-Service $svc).DependentServices | Where-Object Status -eq 'Running' | ForEach-Object Name))
# Restart-Service -Force also starts the dependents again, and one that is not
# ready yet fails the whole restart: measured, DNS would not start just after
# NTDS did, the throw left the KDC stopped, and the next SSH logon failed. So
# the restart's own errors are not fatal; every service that was running is
# started, and started again, until it runs or the deadline passes.
try { Restart-Service $svc -Force } catch { }
$deadline = (Get-Date).AddMinutes(5)
foreach ($s in $running) {
  while ((Get-Service $s).Status -ne 'Running') {
    if ((Get-Date) -gt $deadline) { throw "$s did not come back" }
    try { Start-Service $s } catch { }
    Start-Sleep 3
  }
}
$now = (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name
$inForce = if ($null -eq $now) { 'absent' } else { "$now" }
@{ name = $name; value = $inForce; restarted = $svc; started_again = $running }
