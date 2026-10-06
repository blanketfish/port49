# L44: what the DC logged since a moment (its own clock): the KDC's events
# (KB5014754's mapping events, and the PKINIT ones that mean the setup
# failed), Schannel's, and Directory Service's LDAP bind and channel-binding
# events. Each message is cut at 600 characters.
param([string]$since)
$ErrorActionPreference = 'Stop'
$t = [DateTime]::Parse($since, $null, [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime()
$filters = @(
  @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kerberos-Key-Distribution-Center'; StartTime = $t },
  @{ LogName = 'System'; ProviderName = 'Kerberos-Key-Distribution-Center'; StartTime = $t },
  @{ LogName = 'System'; ProviderName = 'KDC'; StartTime = $t },
  @{ LogName = 'System'; ProviderName = 'Schannel'; StartTime = $t },
  @{ LogName = 'Directory Service'; StartTime = $t; Id = 1220, 2886, 2887, 2888, 2889, 3039, 3074, 3075 }
)
$out = @()
foreach ($f in $filters) {
  $out += @(Get-WinEvent -FilterHashtable $f -ErrorAction SilentlyContinue | ForEach-Object {
    $m = "$($_.Message)" -replace '\s+', ' '
    @{ id = $_.Id; provider = $_.ProviderName; time = $_.TimeCreated.ToUniversalTime().ToString('o');
       message = $m.Substring(0, [Math]::Min(600, $m.Length)) }
  })
}
@{ events = $out }
