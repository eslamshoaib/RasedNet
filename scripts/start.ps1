<#
.SYNOPSIS  Start the RasedNet server over HTTPS (single worker process).
#>
param([string]$BindHost = '127.0.0.1', [int]$Port = 8443)
. "$PSScriptRoot\common.ps1"
$cert = Join-Path $RasedRoot 'certs\rasednet.crt'
$key = Join-Path $RasedRoot 'certs\rasednet.key'
if (-not (Test-Path $cert)) { throw 'الشهادة غير موجودة. شغّل setup.ps1 أو: python -m rasednet gen-cert' }
Push-Location $BackendDir
try { & $Python -m rasednet serve --host $BindHost --port $Port --cert $cert --key $key } finally { Pop-Location }
