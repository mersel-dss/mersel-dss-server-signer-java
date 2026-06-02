#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Mersel DSS Signer API'yi Windows servisi olarak kurar veya kaldırır.

.DESCRIPTION
    Tek-dosyalı operatör scripti. -Action parametresi ile iki mod:

      Install   (default) — WinSW indirir, JAR + XML yerleştirir, .env dosyasını
                            parse edip XML'in <env> bloğuna inject eder, NTFS ACL
                            uygular, servisi kaydeder ve başlatır. Idempotent —
                            çalışan servisi durdurup yeniden install eder.

      Uninstall — Servisi durdurur, WinSW uninstall ile registry kaydını siler,
                  install dizinindeki dosyaları temizler. -KeepLogs ile loglar
                  korunur, -Purge ile C:\ProgramData\mersel-dss-signer da silinir.

    .env dosyasındaki secret'lar XML'e yazılır, XML dosyası NTFS ACL ile sadece
    Administrators + LocalSystem'a okutturulur.

.PARAMETER Action
    Çalıştırılacak işlem: 'Install' (default) veya 'Uninstall'.

.PARAMETER JarPath
    [Install] Spring Boot fat-jar'ın yolu. Belirtilmezse target\mersel-dss-signer-api-*.jar
    otomatik aranır (repo kökünden çalıştırılıyor olmak gerekir).

.PARAMETER EnvFile
    [Install] .env şablonundan üretilen, secret'ları taşıyan env dosyasının yolu.
    Belirtilmezse script'in bulunduğu dizinde mersel-dss-signer.env aranır.

.PARAMETER InstallDir
    Servis dosyalarının yerleşeceği / temizleneceği dizin.
    Default: C:\Program Files\mersel-dss-signer

.PARAMETER WinSwVersion
    [Install] İndirilecek WinSW sürümü (GitHub releases).
    Default: v2.12.0 (yaygın, .NET Framework 4.6.1+).

.PARAMETER JavaHome
    [Install] JAVA_HOME yolu. Belirtilmezse PATH'teki 'java' kullanılır.
    Örnek: -JavaHome "C:\Program Files\Eclipse Adoptium\jdk-8.0.412.8-hotspot"

.PARAMETER ServiceAccount
    [Install] Servisi çalıştıracak hesap. Default: LocalSystem.
    Domain account için: -ServiceAccount "DOMAIN\svc_signer" -ServicePassword (Read-Host -AsSecureString)

.PARAMETER ServicePassword
    [Install] Service account parolası (SecureString).

.PARAMETER ServiceName
    Windows servis adı. Default: mersel-dss-signer.
    Aynı host üzerinde birden fazla tenant için izole servisler kuruyorsan
    her biri için farklı isim ver (örn. MERSEL-DSS-Signer-Api-CGBILGI). WinSW
    exe + XML + jar dosyaları install dizinine bu isimle kopyalanır;
    Uninstall'da da aynı isimle geri çağrılmalı.

.PARAMETER KeepLogs
    [Uninstall] Belirtilirse %InstallDir%\logs içerikleri %TEMP% altına
    yedeklenir (post-mortem analiz için).

.PARAMETER Purge
    [Uninstall] Belirtilirse C:\ProgramData\mersel-dss-signer da silinir.

.EXAMPLE
    .\Install-Service.ps1
    # Default install: JAR otomatik bulunur, env dosyası ./mersel-dss-signer.env

.EXAMPLE
    .\Install-Service.ps1 -JarPath "C:\builds\mersel-dss-signer-api-0.4.0.jar" `
                          -EnvFile "C:\ProgramData\mersel-dss-signer\production.env" `
                          -JavaHome "C:\Program Files\Eclipse Adoptium\jdk-8"

.EXAMPLE
    # Tenant başına izole servis (splat ile)
    $installArgs = @{
        JarPath     = "C:\mersel-dss\mersel-dss-signer-api.jar"
        InstallDir  = "C:\mersel-dss\CGBILGI\Installed"
        ServiceName = "MERSEL-DSS-Signer-Api-CGBILGI"
        EnvFile     = "C:\mersel-dss\CGBILGI\mersel-dss-signer.env"
        JavaHome    = "C:\Program Files\Java\jre1.8.0_281"
    }
    .\Install-Service.ps1 @installArgs

.EXAMPLE
    # Default uninstall (install dizini silinir, ProgramData korunur)
    .\Install-Service.ps1 -Action Uninstall

.EXAMPLE
    # Logları post-mortem için %TEMP%'e yedekle
    .\Install-Service.ps1 -Action Uninstall -KeepLogs

.EXAMPLE
    # Tenant servisini kaldır
    $uninstallArgs = @{
        InstallDir  = "C:\mersel-dss\CGBILGI\Installed"
        ServiceName = "MERSEL-DSS-Signer-Api-CGBILGI"
    }
    .\Install-Service.ps1 -Action Uninstall @uninstallArgs

.EXAMPLE
    # Komple temizlik: install dizini + C:\ProgramData\mersel-dss-signer
    .\Install-Service.ps1 -Action Uninstall -Purge

.NOTES
    Bu scripti administrator PowerShell'inde çalıştırın:
      Start-Process powershell -Verb runAs
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('Install', 'Uninstall')]
    [string]$Action = 'Install',

    # ─── Install parametreleri ─────────────────────────────────────────────────
    [string]$JarPath,
    [string]$EnvFile,
    [string]$WinSwVersion = "v2.12.0",
    [string]$JavaHome,
    [string]$ServiceAccount,
    [securestring]$ServicePassword,

    # ─── Ortak parametreler ────────────────────────────────────────────────────
    [string]$InstallDir = "C:\Program Files\mersel-dss-signer",
    [string]$ServiceName = "mersel-dss-signer",

    # ─── Uninstall parametreleri ───────────────────────────────────────────────
    [switch]$KeepLogs,
    [switch]$Purge
)

$ErrorActionPreference = "Stop"

# ───────────────────────────────────────── helpers
function Write-Info($msg)  { Write-Host ">> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)    { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)   { Write-Host "[X] $msg" -ForegroundColor Red }

function Resolve-RepoRoot {
    # $PSScriptRoot otomatik değişkeni script'in bulunduğu dizini her scope'ta
    # (fonksiyon dahil) doğru döner. $MyInvocation.MyCommand.Path fonksiyon
    # içinde $null olduğu için onu KULLANMA — Join-Path null Path hatası verir.
    return (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}

# ═════════════════════════════════════════════════════════════════════════════
#  INSTALL
# ═════════════════════════════════════════════════════════════════════════════
function Invoke-Install {
    # XML şablonu repo'da "mersel-dss-signer.xml" olarak yatıyor. Servis adı
    # parametre ile değişse bile şablon adı sabit; kopyalanırken $ServiceName.xml
    # olarak hedeflenir (WinSW: exe ve xml aynı baseFileName olmalı).
    $TemplateBaseName = "mersel-dss-signer"
    $ScriptDir   = $PSScriptRoot
    $RepoRoot    = Resolve-RepoRoot
    $XmlTemplate = Join-Path $ScriptDir "$TemplateBaseName.xml"

    if (-not (Test-Path $XmlTemplate)) {
        Write-Err "WinSW XML şablonu bulunamadı: $XmlTemplate"
        exit 1
    }

    # ───────────────────────────────────── JAR yolu
    # JAR adı Maven artifact'ından gelir (mersel-dss-signer-api-*.jar) — ServiceName
    # parametresine bağlı değildir; tenant adı verilse de jar template adıyla aranır.
    if (-not $script:JarPath) {
        $candidate = Get-ChildItem -Path (Join-Path $RepoRoot "target") `
                                   -Filter "$TemplateBaseName-api-*.jar" `
                                   -ErrorAction SilentlyContinue |
                     Sort-Object LastWriteTime -Descending |
                     Select-Object -First 1
        if ($candidate) {
            $script:JarPath = $candidate.FullName
        }
    }
    if (-not $script:JarPath -or -not (Test-Path $script:JarPath)) {
        Write-Err "JAR bulunamadı. Önce 'mvn clean package -DskipTests' çalıştır veya -JarPath ile yol ver."
        exit 1
    }
    Write-Info "JAR kaynağı     : $($script:JarPath)"

    # ───────────────────────────────────── env dosyası
    # Default env dosyası repo'da sabit "mersel-dss-signer.env" olarak yatar.
    # Tenant başına farklı env kullanıyorsan -EnvFile parametresiyle açıkça ver.
    if (-not $script:EnvFile) {
        $script:EnvFile = Join-Path $ScriptDir "$TemplateBaseName.env"
    }
    if (-not (Test-Path $script:EnvFile)) {
        Write-Warn2 "Env dosyası bulunamadı: $($script:EnvFile)"
        Write-Warn2 "Şablondan kopyala: Copy-Item '$ScriptDir\$TemplateBaseName.env.example' '$($script:EnvFile)'"
        Write-Warn2 "Düzenle ve script'i tekrar çalıştır. Şimdilik default değerlerle devam ediliyor."
        $script:EnvFile = $null
    } else {
        Write-Info "Env dosyası     : $($script:EnvFile)"
    }

    # ───────────────────────────────────── Java
    $JavaExe = "java"
    if ($JavaHome) {
        if (-not (Test-Path (Join-Path $JavaHome "bin\java.exe"))) {
            Write-Err "JAVA_HOME'da java.exe yok: $JavaHome\bin\java.exe"
            exit 1
        }
        $JavaExe = (Join-Path $JavaHome "bin\java.exe")
    }
    Write-Info "Java executable : $JavaExe"

    # ───────────────────────────────────── install dizini
    if (-not (Test-Path $InstallDir)) {
        New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null
    }
    $LogDir = Join-Path $InstallDir "logs"
    if (-not (Test-Path $LogDir)) {
        New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
    }
    Write-Ok "Install dizini hazır: $InstallDir"

    # ───────────────────────────────────── WinSW binary indir
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

    # ───────────────────────────────────── JAR'ı yerleştir
    # JAR adı $TemplateBaseName ile sabit — XML şablonundaki <arguments> içindeki
    # "%BASE%\mersel-dss-signer-api.jar" referansıyla uyumlu kalsın diye. Tenant
    # izolasyonu zaten InstallDir farklılaştırmasıyla sağlanıyor; aynı dizine
    # birden fazla servis kurmak desteklenmiyor.
    $JarDest = Join-Path $InstallDir "$TemplateBaseName-api.jar"
    Copy-Item -Path $script:JarPath -Destination $JarDest -Force
    Write-Ok "JAR yerleştirildi → $JarDest"

    # Önceki install'lardan kalmış olabilecek ServiceName-suffix'li JAR'ı temizle
    # (kullanıcı eski sürümden upgrade ediyorsa).
    $LegacyJar = Join-Path $InstallDir "$ServiceName-api.jar"
    if (($LegacyJar -ne $JarDest) -and (Test-Path $LegacyJar)) {
        Remove-Item -Path $LegacyJar -Force -ErrorAction SilentlyContinue
        Write-Info "Eski isim ile yatan JAR silindi: $LegacyJar"
    }

    # ───────────────────────────────────── XML şablonunu üret
    $xmlContent = Get-Content -Path $XmlTemplate -Raw

    # Servis kimliğini ServiceName'e göre güncelle.
    # WinSW Windows registry'ye XML içindeki <id>...</id> etiketinden okuyarak
    # kaydeder — dolayısıyla dosya adı ile servis adı uyuşsun diye burayı da
    # inject etmek ZORUNLU. Aksi halde dosyalar SERVICE-X.exe/xml olarak yatar
    # ama servis adı şablondaki sabit "mersel-dss-signer" olarak kalır.
    # `[regex]::Replace(..., 1)` sadece ilk eşleşmeyi günceller; XML içindeki
    # olası <env name="..."> gibi başka <name> kullanımlarını bozmasın diye.
    $idRegex = [regex]'<id>[^<]*</id>'
    $xmlContent = $idRegex.Replace($xmlContent, "<id>$ServiceName</id>", 1)

    # Display name'i tenant başına ayrıştır (Services.msc'de farkedilebilsin).
    # ServiceName default şablonla aynıysa <name>'i olduğu gibi bırakıyoruz —
    # tek tenantlı kurulumda görsel kirlilik yapmamak için.
    if ($ServiceName -ne $TemplateBaseName) {
        $nameRegex = [regex]'(?s)(<service[^>]*>.*?<name>)[^<]*(</name>)'
        $xmlContent = $nameRegex.Replace($xmlContent, "`${1}Mersel DSS Signer API ($ServiceName)`${2}", 1)
    }

    # Java executable inject (default 'java' PATH; JAVA_HOME verildiyse tam yol)
    if ($JavaHome) {
        $xmlContent = $xmlContent -replace '<executable>java</executable>', "<executable>$JavaExe</executable>"
    }

    # Env dosyası verildiyse <env> bloğunu üret ve inject et
    if ($script:EnvFile) {
        $envLines = @()
        Get-Content -Path $script:EnvFile | ForEach-Object {
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

    # ───────────────────────────────────── XML'i kilitle (NTFS ACL)
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

    # ───────────────────────────────────── servisi kaydet
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

    # ───────────────────────────────────── son durum
    Write-Host ""
    Get-Service -Name $ServiceName | Format-List Name, Status, StartType, DisplayName
    Write-Host ""
    Write-Info "Logları izle      : Get-Content '$LogDir\$ServiceName.out.log' -Wait -Tail 50"
    Write-Info "Durum             : Get-Service $ServiceName"
    Write-Info "Yeniden başlat    : Restart-Service $ServiceName"
    Write-Info "Durdur            : Stop-Service $ServiceName"
    Write-Info "Health kontrolü   : Invoke-WebRequest http://localhost:8085/actuator/health"
    Write-Info "Kaldır            : .\Install-Service.ps1 -Action Uninstall -ServiceName $ServiceName -InstallDir `"$InstallDir`""
}

# ═════════════════════════════════════════════════════════════════════════════
#  UNINSTALL
# ═════════════════════════════════════════════════════════════════════════════
function Invoke-Uninstall {
    $WinSwExe = Join-Path $InstallDir "$ServiceName.exe"

    Write-Info "Hedef servis    : $ServiceName"
    Write-Info "Install dizini  : $InstallDir"

    # ───────────────────────────────────── servisi durdur + uninstall
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

    # ───────────────────────────────────── install dizini
    if (Test-Path $InstallDir) {
        if ($KeepLogs) {
            $logBackup = Join-Path $env:TEMP "$ServiceName-logs-$(Get-Date -Format yyyyMMddHHmmss)"
            $logSrc = Join-Path $InstallDir "logs"
            if (Test-Path $logSrc) {
                Move-Item -Path $logSrc -Destination $logBackup
                Write-Ok "Logları korumak için taşındı: $logBackup"
            }
        }
        Remove-Item -Path $InstallDir -Recurse -Force
        Write-Ok "Install dizini silindi: $InstallDir"
    }

    # ───────────────────────────────────── purge modu
    if ($Purge) {
        $ProgramData = "C:\ProgramData\mersel-dss-signer"
        if (Test-Path $ProgramData) {
            Remove-Item -Path $ProgramData -Recurse -Force
            Write-Ok "ProgramData dizini silindi: $ProgramData"
        }
    } else {
        Write-Warn2 "Operatör tarafından oluşturulan env/cert dosyaları (varsa)"
        Write-Warn2 "C:\ProgramData\mersel-dss-signer altında KORUNDU."
        Write-Warn2 "Komple temizlik için: .\Install-Service.ps1 -Action Uninstall -Purge"
    }

    Write-Ok "Tamamlandı."
}

# ═════════════════════════════════════════════════════════════════════════════
#  DISPATCH
# ═════════════════════════════════════════════════════════════════════════════
switch ($Action) {
    'Install'   { Invoke-Install }
    'Uninstall' { Invoke-Uninstall }
}
