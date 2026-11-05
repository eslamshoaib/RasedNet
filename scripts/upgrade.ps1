<#
.SYNOPSIS
  Offline upgrade. Steps: verify package checksum → encrypted backup → snapshot current code
  → extract new release → install pinned wheels → migrate → health check.
  On any failure run rollback.ps1 with the snapshot printed below.
.PARAMETER Package  Release zip (contains backend\, frontend\dist\, scripts\, wheelhouse\).
.PARAMETER Sha256   Expected SHA-256 of the package, published with the release.
#>
param([Parameter(Mandatory = $true)][string]$Package, [Parameter(Mandatory = $true)][string]$Sha256, [string]$PgBin)
. "$PSScriptRoot\common.ps1"
$actual = (Get-FileHash -Algorithm SHA256 $Package).Hash
if ($actual -ne $Sha256.ToUpper()) { throw 'بصمة حزمة التحديث لا تطابق القيمة المنشورة. أُلغي التحديث.' }

& "$PSScriptRoot\backup.ps1" -PgBin $PgBin

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$snapshot = Join-Path $RasedRoot "releases\pre-upgrade-$stamp"
New-Item -ItemType Directory -Force $snapshot | Out-Null
Copy-Item -Recurse (Join-Path $RasedRoot 'backend\rased'), (Join-Path $RasedRoot 'backend\requirements.lock') -Destination $snapshot
if (Test-Path (Join-Path $RasedRoot 'frontend\dist')) { Copy-Item -Recurse (Join-Path $RasedRoot 'frontend\dist') (Join-Path $snapshot 'dist') }
Write-Host "لقطة الإصدار الحالي: $snapshot"

$staging = Join-Path ([IO.Path]::GetTempPath()) "rased-upgrade-$stamp"
Expand-Archive -LiteralPath $Package -DestinationPath $staging
Copy-Item -Recurse -Force (Join-Path $staging 'backend\rased') (Join-Path $RasedRoot 'backend')
Copy-Item -Force (Join-Path $staging 'backend\requirements.lock') (Join-Path $RasedRoot 'backend')
if (Test-Path (Join-Path $staging 'frontend\dist')) {
    Remove-Item -Recurse -Force (Join-Path $RasedRoot 'frontend\dist') -ErrorAction SilentlyContinue
    Copy-Item -Recurse (Join-Path $staging 'frontend\dist') (Join-Path $RasedRoot 'frontend\dist')
}
& $Python -m pip install --no-index --find-links (Join-Path $staging 'wheelhouse') -r (Join-Path $RasedRoot 'backend\requirements.lock')
if ($LASTEXITCODE -ne 0) { throw "فشل تثبيت الاعتماديات. نفّذ: .\rollback.ps1 -Snapshot '$snapshot'" }
Invoke-Rased @('init-db')
Write-Host "اكتمل التحديث. أعد تشغيل الخدمة ثم نفّذ healthcheck.ps1. للتراجع: .\rollback.ps1 -Snapshot '$snapshot' -BackupFile <أحدث نسخة>" -ForegroundColor Green
