<#
.SYNOPSIS
  Registers RASED as a Windows scheduled task that starts at boot under a dedicated account
  (no third-party service wrapper required). Run elevated.
.PARAMETER ServiceUser  Least-privilege local/domain account that runs the server (NOT a Domain Admin).
#>
param(
    [Parameter(Mandatory = $true)][string]$ServiceUser,
    [string]$BindHost = '0.0.0.0',
    [int]$Port = 8443,
    [switch]$Remove
)
. "$PSScriptRoot\common.ps1"
$taskName = 'RASED Server'
if ($Remove) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false; Write-Host 'تمت إزالة المهمة.'; return }

$credential = Get-Credential -UserName $ServiceUser -Message 'كلمة مرور حساب تشغيل خدمة راصد'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSScriptRoot\start.ps1`" -BindHost $BindHost -Port $Port" `
    -WorkingDirectory $BackendDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings `
    -User $credential.UserName -Password $credential.GetNetworkCredential().Password -RunLevel Limited -Force | Out-Null

# Allow inbound HTTPS only from the internal management subnet you specify here.
Write-Host "تم التسجيل. أضف قاعدة جدار حماية مقيدة، مثال:" -ForegroundColor Green
Write-Host "  New-NetFirewallRule -DisplayName 'RASED HTTPS' -Direction Inbound -Protocol TCP -LocalPort $Port -RemoteAddress 10.0.10.0/24 -Action Allow"
