# L44: promote the VM to the first DC of a new forest, corp.example.com, with
# this build's defaults. The DSRM password arrives on stdin and is never printed.
param([string]$dsrm_password)
$ErrorActionPreference = 'Stop'
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { return @{ promoted = 'already' } }
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
Import-Module ADDSDeployment
$dsrm = ConvertTo-SecureString $dsrm_password -AsPlainText -Force
Install-ADDSForest -DomainName 'corp.example.com' -DomainNetbiosName 'CORP' -InstallDns `
  -SafeModeAdministratorPassword $dsrm -NoRebootOnCompletion -Force -WarningAction SilentlyContinue | Out-Null
# The reboot is left to a timer so this session can answer first.
shutdown.exe /r /t 15 /c 'L44: AD DS promotion' | Out-Null
@{ promoted = 'now' }
