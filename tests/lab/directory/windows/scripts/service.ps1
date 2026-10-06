# L44: stop or start the DC's KDC, for OR-1's cell: a mapped certificate's
# EXTERNAL bind while the KDC that Schannel's S4U2Self needs is down. Kdc is
# the only service this lab stops; the run starts it again at once.
param([string]$name, [string]$state)
$ErrorActionPreference = 'Stop'
if ($name -ne 'Kdc') { throw "not a service this lab stops: $name" }
if ($state -eq 'stop') { Stop-Service Kdc -Force; $want = 'Stopped' }
elseif ($state -eq 'start') { Start-Service Kdc; $want = 'Running' }
else { throw "not a state: $state" }
$deadline = (Get-Date).AddMinutes(3)
while ((Get-Service Kdc).Status -ne $want) {
  if ((Get-Date) -gt $deadline) { throw "Kdc did not reach $want" }
  Start-Sleep 2
}
@{ name = 'Kdc'; status = "$((Get-Service Kdc).Status)" }
