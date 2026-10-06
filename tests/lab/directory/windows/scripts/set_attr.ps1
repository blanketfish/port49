# L44: replace one attribute of one entry with values, or clear it when values
# is empty; the values are read back and returned, so the harness asserts
# exactly what it set.
param([string]$dn, [string]$attribute, [string[]]$values)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$vals = @($values | Where-Object { $_ })
if ($vals.Count -gt 0) { Set-ADObject -Identity $dn -Replace @{ $attribute = [string[]]$vals } }
else { Set-ADObject -Identity $dn -Clear $attribute }
@{ values = @((Get-ADObject -Identity $dn -Properties $attribute).$attribute | ForEach-Object { "$_" }) }
