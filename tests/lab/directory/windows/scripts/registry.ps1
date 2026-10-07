# L44: set (or, with value -1, delete) one of the DC settings the run varies,
# make the service that reads it read it again, and return what is in force.
# A KDC setting restarts the KDC, then starts again every service that depends
# on it and was running before (Restart-Service -Force stops them all). An NTDS
# setting reboots the DC instead: measured, restarting NTDS after setting
# LdapEnforceChannelBinding 2 was followed by lsass crashing (an access
# violation in ntdsai.dll 15s after NTDS came back; wininit restarted the VM).
# The script answers first and a timer reboots, as promote.ps1's does. The answer carries the boot time, so the caller waits for
# a later one.
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
$now = (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name
$inForce = if ($null -eq $now) { 'absent' } else { "$now" }
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
if ($svc -eq 'NTDS') {
  shutdown.exe /r /t 15 /c "L44: $name" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "shutdown /r: exit $LASTEXITCODE" }
  return @{ name = $name; value = $inForce; restarted = 'reboot'; boot = $boot }
}
$running = @(@($svc) + @((Get-Service $svc).DependentServices | Where-Object Status -eq 'Running' | ForEach-Object Name))
# Restart-Service -Force also starts the dependents again, and one that is not
# ready yet fails the whole restart. So the restart's own errors are not
# fatal; every service that was running is started, and started again, until
# it runs or the deadline passes.
try { Restart-Service $svc -Force } catch { }
$deadline = (Get-Date).AddMinutes(5)
foreach ($s in $running) {
  while ((Get-Service $s).Status -ne 'Running') {
    if ((Get-Date) -gt $deadline) { throw "$s did not come back" }
    try { Start-Service $s } catch { }
    Start-Sleep 3
  }
}
@{ name = $name; value = $inForce; restarted = $svc; started_again = $running; boot = $boot }
