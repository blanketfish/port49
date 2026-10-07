# L44: what the DC logged since a moment (its own clock): the KDC's events
# (KB5014754's mapping events, and the PKINIT ones that mean the setup
# failed), Schannel's, and Directory Service's LDAP bind and channel-binding
# events. Each message is cut at 600 characters. It answers `providers`, the
# names it could ask for.
param([string]$since)
$ErrorActionPreference = 'Stop'
$t = [DateTime]::Parse($since, $null, [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime()
# Get-WinEvent throws, past -ErrorAction, for a provider this build has not
# registered ("The parameter is incorrect", an EventLogException): measured,
# the older KDC names here are not registered on the L44 DC. So only the
# names -ListProvider finds are asked for.
$names = 'Microsoft-Windows-Kerberos-Key-Distribution-Center', 'Kerberos-Key-Distribution-Center', 'KDC', 'Schannel'
$registered = @(Get-WinEvent -ListProvider $names -ErrorAction SilentlyContinue | ForEach-Object Name)
$filters = @(foreach ($p in $registered) { @{ LogName = 'System'; ProviderName = $p; StartTime = $t } })
$filters += @{ LogName = 'Directory Service'; StartTime = $t; Id = 1220, 2886, 2887, 2888, 2889, 3039, 3074, 3075 }
$out = @()
foreach ($f in $filters) {
  $out += @(Get-WinEvent -FilterHashtable $f -ErrorAction SilentlyContinue | ForEach-Object {
    $m = "$($_.Message)" -replace '\s+', ' '
    @{ id = $_.Id; provider = $_.ProviderName; time = $_.TimeCreated.ToUniversalTime().ToString('o');
       message = $m.Substring(0, [Math]::Min(600, $m.Length)) }
  })
}
@{ events = $out; providers = $registered }
