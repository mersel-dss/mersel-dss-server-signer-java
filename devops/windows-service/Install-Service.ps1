#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Mersel DSS Signer API'yi Windows servisi olarak kurar.

.DESCRIPTION
    Bu script şu adımları otomatize eder:
      1) WinSW (Windows Service Wrapper) binary'sini indirir (-WinSwVersion ile sürüm değiştirilebilir)
      2) C:\Program Files\mersel-dss-signer dizinini hazırlar
      3) JAR + WinSW XML + WinSW exe'yi yerleştirir
      4) Verilen .env dosyasını parse edip XML'in <env> bloğuna inject eder
      5) Servisi kaydeder ve başlatır

    Idempotent — birden çok kez çalıştırılabilir; çalışan servisi durdurup
    yeniden install eder. .env dosyasındaki secret'lar XML'e yazılır,
    XML dosyası NTFS ACL ile sadece Administrators + LocalSystem'a okutturulur.

.PARAMETER JarPath
    Spring Boot fat-jar'ın yolu. Belirtilmezse target\mersel-dss-signer-api-*.jar
    otomatik aranır (repo kökünden çalıştırılıyor olmak gerekir).

.PARAMETER EnvFile
    .env şablonundan üretilen, secret'ları taşıyan env dosyasının yolu.
    Belirtilmezse script'in bulunduğu dizinde mersel-dss-signer.env aranır.

.PARAMETER InstallDir
    Servis dosyalarının yerleşeceği dizin.
    Default: C:\Program Files\mersel-dss-signer

.PARAMETER WinSwVersion
    İndirilecek WinSW sürümü (GitHub releases).
    Default: v2.12.0 (yaygın, .NET Framework 4.6.1+).

.PARAMETER JavaHome
    JAVA_HOME yolu. Belirtilmezse PATH'teki 'java' kullanılır.
    Örnek: -JavaHome "C:\Program Files\Eclipse Adoptium\jdk-8.0.412.8-hotspot"

.PARAMETER ServiceAccount
    Servisi çalıştıracak hesap. Default: LocalSystem.
    Domain account için: -ServiceAccount "DOMAIN\svc_signer" -ServicePassword (Read-Host -AsSecureString)

.PARAMETER ServicePassword
    Service account parolası (SecureString).

.EXAMPLE
    .\Install-Service.ps1
    # JAR otomatik bulunur, env dosyası ./mersel-dss-signer.env

.EXAMPLE
    .\Install-Service.ps1 -JarPath "C:\builds\mersel-dss-signer-api-0.4.0.jar" `
                          -EnvFile "C:\ProgramData\mersel-dss-signer\production.env" `
                          -JavaHome "C:\Program Files\Eclipse Adoptium\jdk-8"

.NOTES
    Bu scripti administrator PowerShell'inde çalıştırın:
      Start-Process powershell -Verb runAs
#>

[CmdletBinding()]
param(
    [string]$JarPath,
    [string]$EnvFile,
    [string]$InstallDir = "C:\Program Files\mersel-dss-signer",
    [string]$WinSwVersion = "v2.12.0",
    [string]$JavaHome,
    [string]$ServiceAccount,
    [securestring]$ServicePassword
)

$ErrorActionPreference = "Stop"

# ───────────────────────────────────────── helpers
function Write-Info($msg)  { Write-Host "› $msg" -ForegroundColor Cyan }
function Write-Ok($msg)    { Write-Host "✓ $msg" -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host "⚠ $msg" -ForegroundColor Yellow }
function Write-Err($msg)   { Write-Host "✗ $msg" -ForegroundColor Red }

function Resolve-RepoRoot {
    # Script bulunduğu dizin: devops\windows-service\
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    return (Resolve-Path (Join-Path $scriptDir "..\..")).Path
}

# ───────────────────────────────────────── sabit değerler
$ServiceName = "mersel-dss-signer"
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot    = Resolve-RepoRoot
$XmlTemplate = Join-Path $ScriptDir "$ServiceName.xml"

if (-not (Test-Path $XmlTemplate)) {
    Write-Err "WinSW XML şablonu bulunamadı: $XmlTemplate"
    exit 1
}

# ───────────────────────────────────────── JAR yolu
if (-not $JarPath) {
    $candidate = Get-ChildItem -Path (Join-Path $RepoRoot "target") `
                               -Filter "$ServiceName-api-*.jar" `
                               -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending |
                 Select-Object -First 1
    if ($candidate) {
        $JarPath = $candidate.FullName
    }
}
if (-not $JarPath -or -not (Test-Path $JarPath)) {
    Write-Err "JAR bulunamadı. Önce 'mvn clean package -DskipTests' çalıştır veya -JarPath ile yol ver."
    exit 1
}
Write-Info "JAR kaynağı     : $JarPath"

# ───────────────────────────────────────── env dosyası
if (-not $EnvFile) {
    $EnvFile = Join-Path $ScriptDir "$ServiceName.env"
}
if (-not (Test-Path $EnvFile)) {
    Write-Warn2 "Env dosyası bulunamadı: $EnvFile"
    Write-Warn2 "Şablondan kopyala: Copy-Item '$ScriptDir\$ServiceName.env.example' '$EnvFile'"
    Write-Warn2 "Düzenle ve script'i tekrar çalıştır. Şimdilik default değerlerle devam ediliyor."
    $EnvFile = $null
} else {
    Write-Info "Env dosyası     : $EnvFile"
}

# ───────────────────────────────────────── Java
$JavaExe = "java"
if ($JavaHome) {
    if (-not (Test-Path (Join-Path $JavaHome "bin\java.exe"))) {
        Write-Err "JAVA_HOME'da java.exe yok: $JavaHome\bin\java.exe"
        exit 1
    }
    $JavaExe = (Join-Path $JavaHome "bin\java.exe")
}
Write-Info "Java executable : $JavaExe"

# ───────────────────────────────────────── install dizini
if (-not (Test-Path $InstallDir)) {
    New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null
}
$LogDir = Join-Path $InstallDir "logs"
if (-not (Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
}
Write-Ok "Install dizini hazır: $InstallDir"

# ───────────────────────────────────────── WinSW binary indir
$WinSwExe = Join-Path $InstallDir "$ServiceName.exe"
if (-not (Test-Path $WinSwExe)) {
    $WinSwUrl = "https://github.com/winsw/winsw/releases/download/$WinSwVersion/WinSW.NET461.exe"
    Write-Info "WinSW indiriliyor → $WinSwUrl"
    try {
        # TLS 1.2 — GitHub varsayılan
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $WinSwUrl -OutFile $WinSwExe -UseBasicParsing
        Write-Ok "WinSW indirildi: $WinSwExe"
    } catch {
        Write-Err "WinSW indirilemedi: $_"
        Write-Warn2 "İnternet yok ya da proxy/firewall engelliyor. Manuel indirip $WinSwExe yoluna koy:"
        Write-Warn2 "  $WinSwUrl"
        exit 1
    }
} else {
    Write-Info "WinSW zaten var, atlanıyor: $WinSwExe"
}

# ───────────────────────────────────────── JAR'ı yerleştir
$JarDest = Join-Path $InstallDir "$ServiceName-api.jar"
Copy-Item -Path $JarPath -Destination $JarDest -Force
Write-Ok "JAR yerleştirildi → $JarDest"

# ───────────────────────────────────────── XML şablonunu üret
$xmlContent = Get-Content -Path $XmlTemplate -Raw

# Java executable inject (default 'java' PATH; JAVA_HOME verildiyse tam yol)
if ($JavaHome) {
    $xmlContent = $xmlContent -replace '<executable>java</executable>', "<executable>$JavaExe</executable>"
}

# Env dosyası verildiyse <env> bloğunu üret ve inject et
if ($EnvFile) {
    $envLines = @()
    Get-Content -Path $EnvFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#")) {
            $idx = $line.IndexOf("=")
            if ($idx -gt 0) {
                $key = $line.Substring(0, $idx).Trim()
                $val = $line.Substring($idx + 1).Trim()
                # XML escape — & < > " '
                $val = $val -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'","&apos;"
                $envLines += "    <env name=`"$key`" value=`"$val`" />"
            }
        }
    }

    if ($envLines.Count -gt 0) {
        $envBlock = "<!-- BEGIN_ENV_INJECTION (Install-Service.ps1 tarafından üretildi) -->`r`n" +
                    ($envLines -join "`r`n") +
                    "`r`n    <!-- END_ENV_INJECTION -->"

        $pattern = '(?s)<!-- BEGIN_ENV_INJECTION.*?END_ENV_INJECTION -->'
        $xmlContent = [System.Text.RegularExpressions.Regex]::Replace($xmlContent, $pattern, $envBlock)

        Write-Ok "Env dosyasından $($envLines.Count) değişken XML'e inject edildi"
    }
}

# Service account inject (opsiyonel)
if ($ServiceAccount -and $ServicePassword) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ServicePassword)
    try {
        $plainPwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        $plainPwd = $plainPwd -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'","&apos;"
        $svcAcctXml = @"
<serviceaccount>
        <username>$ServiceAccount</username>
        <password>$plainPwd</password>
        <allowservicelogon>true</allowservicelogon>
    </serviceaccount>
"@
        # Yorum hâlindeki serviceaccount bloğunu açık hâlle değiştir
        $xmlContent = $xmlContent -replace '(?s)<!-- <serviceaccount>.*?</serviceaccount> -->', $svcAcctXml
        Write-Ok "Service account inject edildi: $ServiceAccount"
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

$XmlDest = Join-Path $InstallDir "$ServiceName.xml"
$xmlContent | Out-File -FilePath $XmlDest -Encoding UTF8 -Force
Write-Ok "XML yerleştirildi → $XmlDest"

# ───────────────────────────────────────── XML'i kilitle (NTFS ACL)
# Sadece SYSTEM ve Administrators okuyabilsin (PIN sızıntısı önleme)
try {
    $acl = Get-Acl $XmlDest
    $acl.SetAccessRuleProtection($true, $false)  # inheritance off
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "Allow")
    $adminRule  = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "Allow")
    $acl.AddAccessRule($systemRule)
    $acl.AddAccessRule($adminRule)
    Set-Acl -Path $XmlDest -AclObject $acl
    Write-Ok "XML dosyasına restrictive ACL uygulandı (sadece SYSTEM + Administrators)"
} catch {
    Write-Warn2 "ACL uygulanamadı: $_"
    Write-Warn2 "Manuel: icacls `"$XmlDest`" /inheritance:r /grant:r `"SYSTEM:F`" `"Administrators:F`""
}

# ───────────────────────────────────────── servisi kaydet
Push-Location $InstallDir
try {
    # Çalışan servisi durdur (varsa) ve uninstall et (XML değişikliği uygulansın diye)
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Info "Mevcut servis bulundu, durdurulup yeniden kayıt edilecek"
        if ($existing.Status -eq "Running") {
            Stop-Service -Name $ServiceName -Force
            Write-Ok "Servis durduruldu"
        }
        & $WinSwExe uninstall
        Start-Sleep -Seconds 2
    }

    & $WinSwExe install
    if ($LASTEXITCODE -ne 0) {
        throw "WinSW install başarısız (exit code $LASTEXITCODE)"
    }
    Write-Ok "Servis kaydedildi"

    & $WinSwExe start
    if ($LASTEXITCODE -ne 0) {
        Write-Warn2 "Servis başlatılamadı (exit code $LASTEXITCODE). Logları kontrol et: $LogDir"
    } else {
        Write-Ok "Servis başlatıldı"
    }
} finally {
    Pop-Location
}

# ───────────────────────────────────────── son durum
Write-Host ""
Get-Service -Name $ServiceName | Format-List Name, Status, StartType, DisplayName
Write-Host ""
Write-Info "Logları izle      : Get-Content '$LogDir\$ServiceName.out.log' -Wait -Tail 50"
Write-Info "Durum             : Get-Service $ServiceName"
Write-Info "Yeniden başlat    : Restart-Service $ServiceName"
Write-Info "Durdur            : Stop-Service $ServiceName"
Write-Info "Health kontrolü   : Invoke-WebRequest http://localhost:8085/actuator/health"
Write-Info "Kaldır            : .\Uninstall-Service.ps1"
