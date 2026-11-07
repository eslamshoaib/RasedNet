<#
.SYNOPSIS
  Restores an encrypted backup. The file is verified (SHA-256 + GCM tag) BEFORE anything in
  the database is touched. Stop the RasedNet server first.
#>
param([Parameter(Mandatory = $true)][string]$BackupFile, [string]$PgBin, [switch]$Force)
. "$PSScriptRoot\common.ps1"
if (-not (Test-Path $BackupFile)) { throw "الملف غير موجود: $BackupFile" }

$sumFile = "$BackupFile.sha256"
if (Test-Path $sumFile) {
    $expected = (Get-Content $sumFile -Raw).Split(' ')[0].Trim().ToLower()
    $actual = (Get-FileHash -Algorithm SHA256 $BackupFile).Hash.ToLower()
    if ($expected -ne $actual) { throw 'بصمة SHA-256 لا تطابق: الملف تالف أو معدّل. لن تتم الاستعادة.' }
} else { Write-Warning 'لا يوجد ملف بصمة .sha256؛ سيتم الاعتماد على التحقق المدمج في التشفير فقط.' }

$plain = Join-Path ([IO.Path]::GetTempPath()) ("rasednet-restore-" + [Guid]::NewGuid().ToString('N') + '.dump')
try {
    Invoke-Rased @('decrypt-file', $BackupFile, $plain)   # throws on wrong passphrase / tampering
    $pg = Get-PgConnection
    if (-not $Force) {
        $answer = Read-Host "سيتم استبدال بيانات قاعدة البيانات '$($pg.Database)' على $($pg.Host). اكتب RESTORE للمتابعة"
        if ($answer -ne 'RESTORE') { Write-Host 'أُلغيت الاستعادة.'; return }
    }
    $pgRestore = Find-PgTool 'pg_restore' $PgBin
    $env:PGPASSWORD = $pg.Password
    try {
        & $pgRestore --clean --if-exists --no-owner --single-transaction --exit-on-error `
            --host $pg.Host --port $pg.Port --username $pg.User --dbname $pg.Database $plain
        if ($LASTEXITCODE -ne 0) { throw 'فشل pg_restore؛ لم تُطبق أي تغييرات (معاملة واحدة).' }
    } finally { Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue }
    Invoke-Rased @('init-db')   # apply any newer migrations on top of the restored schema
    Write-Host 'تمت الاستعادة بنجاح.' -ForegroundColor Green
} finally {
    if (Test-Path $plain) { Remove-Item -LiteralPath $plain -Force }
}
