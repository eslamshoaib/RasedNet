<#
.SYNOPSIS
  Encrypted PostgreSQL backup: pg_dump (custom format) → AES-256-GCM → .sha256 checksum.
  The plaintext dump is deleted immediately after encryption.
  Passphrase: $env:RASEDNET_BACKUP_PASSPHRASE, otherwise prompted. Keep it OFF this server.
#>
param([string]$OutDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'backups'), [string]$PgBin, [int]$KeepDays = 30)
. "$PSScriptRoot\common.ps1"
$pg = Get-PgConnection
$pgDump = Find-PgTool 'pg_dump' $PgBin
New-Item -ItemType Directory -Force $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$plain = Join-Path $OutDir "rasednet-$stamp.dump"
$encrypted = "$plain.enc"

$env:PGPASSWORD = $pg.Password
try {
    & $pgDump --format=custom --no-owner --host $pg.Host --port $pg.Port --username $pg.User --file $plain $pg.Database
    if ($LASTEXITCODE -ne 0) { throw 'فشل pg_dump' }
} finally { Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue }

try { Invoke-Rased @('encrypt-file', $plain, $encrypted) }
finally { if (Test-Path $plain) { Remove-Item -LiteralPath $plain -Force } }

Get-ChildItem $OutDir -Filter 'rasednet-*.dump.enc*' | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$KeepDays) } | Remove-Item -Force
Write-Host "تم إنشاء النسخة الاحتياطية: $encrypted" -ForegroundColor Green
