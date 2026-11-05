<#
.SYNOPSIS  Health check: exit code 0 when the server and database are healthy.
#>
param([string]$Url = 'https://127.0.0.1:8443/api/health', [switch]$SkipCertificateCheck)
[Console]::OutputEncoding = [Text.Encoding]::UTF8
if ($SkipCertificateCheck) {
    # Windows PowerShell 5.1: accept the local self-signed certificate for this check only.
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
}
try {
    $r = Invoke-RestMethod -Uri $Url -TimeoutSec 10
    Write-Host "الحالة: $($r.status) — قاعدة البيانات: $($r.database) — الإصدار: $($r.version)"
    if ($r.status -eq 'ok') { exit 0 } else { exit 1 }
} catch {
    Write-Host "الخدمة لا تستجيب: $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}
