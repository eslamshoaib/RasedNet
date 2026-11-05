<#
.SYNOPSIS
  Roll back to the code snapshot taken by upgrade.ps1 and, because a newer migration may have
  changed the schema, restore the pre-upgrade encrypted database backup. Stop the server first.
#>
param([Parameter(Mandatory = $true)][string]$Snapshot, [Parameter(Mandatory = $true)][string]$BackupFile, [string]$Wheelhouse, [string]$PgBin)
. "$PSScriptRoot\common.ps1"
if (-not (Test-Path (Join-Path $Snapshot 'rased'))) { throw "اللقطة غير صالحة: $Snapshot" }
Remove-Item -Recurse -Force (Join-Path $BackendDir 'rased')
Copy-Item -Recurse (Join-Path $Snapshot 'rased') $BackendDir
Copy-Item -Force (Join-Path $Snapshot 'requirements.lock') $BackendDir
if (Test-Path (Join-Path $Snapshot 'dist')) {
    Remove-Item -Recurse -Force (Join-Path $RasedRoot 'frontend\dist') -ErrorAction SilentlyContinue
    Copy-Item -Recurse (Join-Path $Snapshot 'dist') (Join-Path $RasedRoot 'frontend\dist')
}
$lock = Join-Path $BackendDir 'requirements.lock'
if ($Wheelhouse) { & $Python -m pip install --no-index --find-links $Wheelhouse -r $lock } else { & $Python -m pip install -r $lock }
& "$PSScriptRoot\restore.ps1" -BackupFile $BackupFile -PgBin $PgBin
Write-Host 'تم التراجع إلى الإصدار السابق. أعد تشغيل الخدمة وتحقق عبر healthcheck.ps1.' -ForegroundColor Green
