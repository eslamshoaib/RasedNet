# Shared helpers for RasedNet operations scripts (dot-sourced).
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$OutputEncoding = [Text.Encoding]::UTF8

$script:RasedRoot = Split-Path -Parent $PSScriptRoot
$script:BackendDir = Join-Path $RasedRoot 'backend'
$script:Python = Join-Path $BackendDir '.venv\Scripts\python.exe'
$script:EnvFile = Join-Path $BackendDir '.env'

function Read-RasedEnv {
    if (-not (Test-Path $EnvFile)) { throw "ملف الإعدادات غير موجود: $EnvFile. شغّل setup.ps1 أولاً." }
    $values = @{}
    foreach ($line in Get-Content -LiteralPath $EnvFile -Encoding UTF8) {
        if ($line -match '^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$') { $values[$Matches[1]] = $Matches[2] }
    }
    return $values
}

function Get-PgConnection {
    # Parses postgresql+psycopg://user:password@host:port/database
    $url = (Read-RasedEnv)['RASEDNET_DATABASE_URL']
    if (-not $url) { throw 'RASEDNET_DATABASE_URL غير محدد في ملف .env' }
    $uri = [Uri]($url -replace '^postgresql\+psycopg://', 'postgresql://')
    $userInfo = $uri.UserInfo.Split(':', 2)
    return [pscustomobject]@{
        Host     = $uri.Host
        Port     = if ($uri.Port -gt 0) { $uri.Port } else { 5432 }
        User     = [Uri]::UnescapeDataString($userInfo[0])
        Password = if ($userInfo.Count -gt 1) { [Uri]::UnescapeDataString($userInfo[1]) } else { '' }
        Database = $uri.AbsolutePath.TrimStart('/')
    }
}

function Find-PgTool([string]$Name, [string]$PgBin) {
    if ($PgBin) { $candidate = Join-Path $PgBin "$Name.exe"; if (Test-Path $candidate) { return $candidate } }
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $installed = Get-ChildItem 'C:\Program Files\PostgreSQL\*\bin' -Directory -ErrorAction SilentlyContinue | Sort-Object FullName -Descending
    foreach ($dir in $installed) { $candidate = Join-Path $dir.FullName "$Name.exe"; if (Test-Path $candidate) { return $candidate } }
    throw "تعذر العثور على $Name. مرّر -PgBin بمسار مجلد bin الخاص بـ PostgreSQL."
}

function Invoke-Rased([string[]]$Arguments) {
    Push-Location $BackendDir
    try {
        & $Python -m rasednet @Arguments
        if ($LASTEXITCODE -ne 0) { throw "فشل الأمر: rasednet $($Arguments -join ' ')" }
    } finally { Pop-Location }
}
