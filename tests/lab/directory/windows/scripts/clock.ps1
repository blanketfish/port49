# L44: the DC's clock, for the skew check and as the "since" of an events read.
param()
$ErrorActionPreference = 'Stop'
@{ utc_now = [DateTime]::UtcNow.ToString('o') }
