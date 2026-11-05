<#
.SYNOPSIS
  First-time installation of RASED on Windows (run from an elevated or normal PowerShell).
.DESCRIPTION
  1. Creates backend\.venv with Python 3.12 and installs the pinned dependencies
     (offline: pass -Wheelhouse with a folder prepared by `pip download -r requirements.lock`).
  2. Writes backend\.env (database URL, secure cookies).
  3. Applies migrations, creates the first administrator, generates a local TLS certificate.
  4. Builds the frontend if Node.js is available and no prebuilt dist exists.
.EXAMPLE
  .\setup.ps1 -DatabaseUrl 'postgresql+psycopg://rased:CHANGE_ME@127.0.0.1:5432/rased' -AdminUser admin -Hostname rased.corp.local
#>
param(
    [Parameter(Mandatory = $true)][string]$DatabaseUrl,
    [string]$AdminUser = 'admin',
    [string[]]$Hostname = @(),
    [string]$Wheelhouse
)
. "$PSScriptRoot\common.ps1"

Write-Host '== التحقق من Python 3.12 ==' -ForegroundColor Cyan
& py -3.12 --version
if ($LASTEXITCODE -ne 0) { throw 'Python 3.12 غير مثبت. ثبّته من الحزمة المعتمدة ثم أعد المحاولة.' }

if (-not (Test-Path $Python)) { & py -3.12 -m venv (Join-Path $BackendDir '.venv') }
$lock = Join-Path $BackendDir 'requirements.lock'
if ($Wheelhouse) {
    & $Python -m pip install --no-index --find-links $Wheelhouse -r $lock
} else {
    & $Python -m pip install -r $lock
}
if ($LASTEXITCODE -ne 0) { throw 'فشل تثبيت الاعتماديات' }

if (-not (Test-Path $EnvFile)) {
    # UTF-8 *without* BOM: a BOM would corrupt the first key name when the app reads .env.
    [IO.File]::WriteAllLines($EnvFile, [string[]]@(
        "RASED_DATABASE_URL=$DatabaseUrl",
        'RASED_COOKIE_SECURE=true',
        "RASED_LOG_DIR=$(Join-Path $RasedRoot 'logs')"
    ), (New-Object System.Text.UTF8Encoding($false)))
    # Restrict the file that contains the database password to the current user and Administrators.
    icacls $EnvFile /inheritance:r /grant:r "$($env:USERNAME):(R,W)" '*S-1-5-32-544:(F)' | Out-Null
    Write-Host "تم إنشاء $EnvFile"
}

Invoke-Rased @('init-db')
Write-Host "== إنشاء حساب المسؤول $AdminUser ==" -ForegroundColor Cyan
Push-Location $BackendDir; try { & $Python -m rased create-admin --username $AdminUser } finally { Pop-Location }

$certDir = Join-Path $RasedRoot 'certs'
if (-not (Test-Path (Join-Path $certDir 'rased.crt'))) {
    $certArgs = @('gen-cert', '--out-dir', $certDir)
    foreach ($h in $Hostname) { $certArgs += @('--hostname', $h) }
    Invoke-Rased $certArgs
    icacls (Join-Path $certDir 'rased.key') /inheritance:r /grant:r "$($env:USERNAME):(R)" '*S-1-5-32-544:(F)' | Out-Null
}

$dist = Join-Path $RasedRoot 'frontend\dist\index.html'
if (-not (Test-Path $dist)) {
    if (Get-Command npm -ErrorAction SilentlyContinue) {
        Push-Location (Join-Path $RasedRoot 'frontend')
        try { npm ci; npm run build; npm run check-offline } finally { Pop-Location }
    } else {
        Write-Warning 'Node.js غير متوفر ولا توجد واجهة مبنية مسبقاً (frontend\dist). انسخ مجلد dist المبني من جهاز البناء.'
    }
}
Write-Host 'اكتمل التثبيت. للتشغيل: .\scripts\start.ps1 ثم افتح https://localhost:8443' -ForegroundColor Green
