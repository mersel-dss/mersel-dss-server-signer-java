#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Mersel DSS Signer API Windows servisini kaldırır.

.DESCRIPTION
    1) Servisi durdurur
    2) WinSW uninstall ile Windows service registry kaydını siler
    3) Install dizinindeki dosyaları siler (-KeepLogs ile logları korur)
    4) -Purge ile env dosyasını da siler

.PARAMETER InstallDir
    Servis dosyalarının bulunduğu dizin.
    Default: C:\Program Files\mersel-dss-signer

.PARAMETER KeepLogs
    Belirtilirse %InstallDir%\logs içerikleri korunur (post-mortem analiz için).

.PARAMETER Purge
    Belirtilirse env dosyası ve C:\ProgramData\mersel-dss-signer da silinir.

.EXAMPLE
    .\Uninstall-Service.ps1
    # Default: install dizini tamamen silinir, env dosyası varsa silinir.

.EXAMPLE
    .\Uninstall-Service.ps1 -KeepLogs
    # Logları korur, post-mortem için.

.EXAMPLE
    .\Uninstall-Service.ps1 -Purge
    # Komple temizlik: install dizini + C:\ProgramData\mersel-dss-signer.
#>

[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\mersel-dss-signer",
    [switch]$KeepLogs,
    [switch]$Purge
)

$ErrorActionPreference = "Stop"

function Write-Info($msg)  { Write-Host "› $msg" -ForegroundColor Cyan }
function Write-Ok($msg)    { Write-Host "✓ $msg" -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host "⚠ $msg" -ForegroundColor Yellow }

$ServiceName = "mersel-dss-signer"
$WinSwExe = Join-Path $InstallDir "$ServiceName.exe"

# ───────────────────────────────────────── servisi durdur + uninstall
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -eq "Running") {
        try {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            Write-Ok "Servis durduruldu"
        } catch {
            Write-Warn2 "Stop-Service başarısız: $_  (devam ediliyor)"
        }
    }

    if (Test-Path $WinSwExe) {
        Push-Location $InstallDir
        try {
            & $WinSwExe uninstall
            Write-Ok "Windows service registry kaydı silindi"
        } catch {
            Write-Warn2 "WinSW uninstall hatası: $_"
        } finally {
            Pop-Location
        }
    } else {
        # WinSW yoksa sc.exe ile zorla sil
        & sc.exe delete $ServiceName | Out-Null
        Write-Ok "sc.exe ile servis silindi"
    }
} else {
    Write-Info "Servis zaten yok, atlanıyor"
}

# ───────────────────────────────────────── install dizini
if (Test-Path $InstallDir) {
    if ($KeepLogs) {
        $logBackup = Join-Path $env:TEMP "mersel-dss-signer-logs-$(Get-Date -Format yyyyMMddHHmmss)"
        $logSrc = Join-Path $InstallDir "logs"
        if (Test-Path $logSrc) {
            Move-Item -Path $logSrc -Destination $logBackup
            Write-Ok "Logları korumak için taşındı: $logBackup"
        }
    }
    Remove-Item -Path $InstallDir -Recurse -Force
    Write-Ok "Install dizini silindi: $InstallDir"
}

# ───────────────────────────────────────── purge modu
if ($Purge) {
    $ProgramData = "C:\ProgramData\mersel-dss-signer"
    if (Test-Path $ProgramData) {
        Remove-Item -Path $ProgramData -Recurse -Force
        Write-Ok "ProgramData dizini silindi: $ProgramData"
    }
} else {
    Write-Warn2 "Operatör tarafından oluşturulan env/cert dosyaları (varsa)"
    Write-Warn2 "C:\ProgramData\mersel-dss-signer altında KORUNDU."
    Write-Warn2 "Komple temizlik için: .\Uninstall-Service.ps1 -Purge"
}

Write-Ok "Tamamlandı."
