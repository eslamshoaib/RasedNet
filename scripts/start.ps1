<#
.SYNOPSIS  Start the RASED server over HTTPS (single worker process).
#>
param([string]$BindHost = '127.0.0.1', [int]$Port = 8443)
. "$PSScriptRoot\common.ps1"
$cert = Join-Path $RasedRoot 'certs\rased.crt'
$key = Join-Path $RasedRoot 'certs\rased.key'
if (-not (Test-Path $cert)) { throw 'الشهادة غير موجودة. شغّل setup.ps1 أو: python -m rased gen-cert' }
Push-Location $BackendDir
try { & $Python -m rased serve --host $BindHost --port $Port --cert $cert --key $key } finally { Pop-Location }
