# Windows Servisi

> **TL;DR** — JAR'ı build et, `.env`'i doldur, `Install-Service.ps1` çalıştır (admin PowerShell). Tamam.

Mersel DSS Signer API'yi Windows Server (2019 / 2022) veya Windows 10/11 üzerinde **otomatik başlayan, restart-on-failure ve Event Viewer'a düşen** bir Windows servisi olarak çalıştırmak içindir.

İki yol gösteriyoruz:

- **Birincil:** [WinSW](https://github.com/winsw/winsw) — açık kaynak, XML config, .NET Framework 4.6.1+. Production için önerimiz.
- **Alternatif:** [NSSM](https://nssm.cc/) — yine yaygın, GUI'li wrapper. Hızlı PoC için.

---

## İçindekiler

- [1. Klasör İçeriği](#1-klasör-içeriği)
- [2. Ön Koşullar](#2-ön-koşullar)
- [3. Hızlı Kurulum (WinSW)](#3-hızlı-kurulum-winsw)
- [4. Env Dosyası](#4-env-dosyası)
- [5. Manuel Kurulum (WinSW)](#5-manuel-kurulum-winsw)
- [6. NSSM Alternatifi](#6-nssm-alternatifi)
- [7. Operasyon Komutları](#7-operasyon-komutları)
- [8. PFX vs HSM Senaryoları](#8-pfx-vs-hsm-senaryoları)
- [9. Güvenlik (NTFS ACL, Service Account)](#9-güvenlik-ntfs-acl-service-account)
- [10. Reverse Proxy (IIS / nginx) Önerisi](#10-reverse-proxy-iis--nginx-önerisi)
- [11. Sorun Giderme](#11-sorun-giderme)
- [12. Kaldırma](#12-kaldırma)

---

## 1. Klasör İçeriği

```
devops/windows-service/
├── mersel-dss-signer.xml            # WinSW yapılandırma şablonu
├── mersel-dss-signer.env.example    # Env şablonu (CRLF satır sonu)
├── Install-Service.ps1              # Otomatik kurulum (WinSW indirir, XML inject eder)
├── Uninstall-Service.ps1            # Temiz kaldırma (-KeepLogs, -Purge)
└── README.md                        # Bu dosya
```

---

## 2. Ön Koşullar

| Bileşen | Sürüm | Kontrol |
|---|---|---|
| Windows | Server 2019/2022 veya 10/11 | `winver` |
| .NET Framework | 4.6.1+ (WinSW NET461 build için) | Sistemde default |
| JDK / JRE | 8+ | `java -version` |
| Maven | 3.6+ (sadece build için) | `mvn -v` |
| PowerShell | 5.1+ | `$PSVersionTable.PSVersion` |
| İnternet | WinSW download için ([release sayfası](https://github.com/winsw/winsw/releases)) | İlk install'da |

**Admin haklarıyla PowerShell aç:**
```powershell
Start-Process powershell -Verb runAs
```

**ExecutionPolicy** kısıtlıysa script'ler için bir kerelik geçiş:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

---

## 3. Hızlı Kurulum (WinSW)

```powershell
# 1) Repo kökünden JAR üret
mvn clean package -DskipTests

# 2) Env şablonunu kopyala ve düzenle
cd .\devops\windows-service
Copy-Item .\mersel-dss-signer.env.example .\mersel-dss-signer.env
notepad .\mersel-dss-signer.env
# → CERTIFICATE_PIN, PFX_PATH / PKCS11_LIBRARY, TS_USER_* doldurulur

# 3) Servisi kur (admin PowerShell şart)
.\Install-Service.ps1

# 4) Sağlık kontrolü
Get-Service mersel-dss-signer
Invoke-WebRequest http://localhost:8085/actuator/health -UseBasicParsing |
    Select-Object -ExpandProperty Content
```

Script otomatik olarak:

1. `C:\Program Files\mersel-dss-signer\` dizinini hazırlar
2. WinSW binary'sini GitHub'tan indirir (`v2.12.0` default, `-WinSwVersion` ile değiştirilebilir)
3. JAR'ı kopyalar
4. `.env` dosyasındaki KEY=VALUE'ları XML'in `<env>` bloklarına inject eder
5. XML dosyasına restrictive NTFS ACL uygular (sadece SYSTEM + Administrators okuyabilir)
6. `winsw install` + `winsw start` çağırır

---

## 4. Env Dosyası

`mersel-dss-signer.env` operatör tarafından oluşturulur (`.example`'dan kopyalanır). Repo'ya **commit edilmez** — `.gitignore` zaten `*.env`'i tutar.

### Önemli Değişkenler

| Değişken | Senaryo | Açıklama |
|---|---|---|
| `CERTIFICATE_PIN` | her senaryo | PFX parolası veya HSM PIN'i |
| `PFX_PATH` | PFX | PFX dosyasının tam yolu |
| `CERTIFICATE_ALIAS` | her senaryo | Alias (default: `1`) |
| `PKCS11_LIBRARY` | HSM | AKİS DLL yolu (`C:\Windows\System32\akisp11.dll`) |
| `PKCS11_SLOT` / `PKCS11_SLOT_LIST_INDEX` | HSM | -1 = auto |
| `IS_TUBITAK_TSP` | TSP | TÜBİTAK TSP modu (otomatik tespit) |
| `TS_USER_ID` / `TS_USER_PASSWORD` | TSP | TÜBİTAK abone kimlik bilgileri |
| `XADES_SIGNING_TIME_ZONE` | XAdES | `+03:00` (default), `Z` (ETSI saf yorumu) — [issue #7](https://github.com/mersel-dss/server-signer-java/issues/7) |
| `SERVER_PORT` | runtime | HTTP port (default 8085) |
| `LOG_LEVEL` | runtime | `INFO` / `DEBUG` |
| `SPRING_PROFILES_ACTIVE` | runtime | Production'da **boş**; test için `local,pfx-kurum01-rsa2048` ([docs/RUN_PROFILES.md](../../docs/RUN_PROFILES.md)) |

Tam liste: [`mersel-dss-signer.env.example`](./mersel-dss-signer.env.example)

> **Önemli**: `.env` dosyasını XML'e inject ettiğimiz için sonradan `.env`'i değiştirsen bile servis görmez. Değişiklik sonrası `Install-Service.ps1`'i **yeniden çalıştır** — XML güncellenir ve servis restart edilir.

---

## 5. Manuel Kurulum (WinSW)

Script kullanmak istemiyorsan ya da troubleshooting yapıyorsan:

```powershell
# 1) İndir
$installDir = "C:\Program Files\mersel-dss-signer"
New-Item -Path $installDir -ItemType Directory -Force
$winsw = "$installDir\mersel-dss-signer.exe"
Invoke-WebRequest `
    -Uri "https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW.NET461.exe" `
    -OutFile $winsw

# 2) JAR + XML kopyala
Copy-Item .\target\mersel-dss-signer-api-*.jar `
          "$installDir\mersel-dss-signer-api.jar"
Copy-Item .\devops\windows-service\mersel-dss-signer.xml `
          "$installDir\mersel-dss-signer.xml"

# 3) XML'i düzenle (env değerleri MANUEL inject)
notepad "$installDir\mersel-dss-signer.xml"
#   <env name="CERTIFICATE_PIN" value="..."/>  vs.
#   yorum işaretlerini kaldır ve değerleri yaz

# 4) Servis kayıt + başlat
& $winsw install
& $winsw start

# 5) Kontrol
Get-Service mersel-dss-signer
```

---

## 6. NSSM Alternatifi

NSSM grafik yardımıyla servis tanımı yapan basit bir wrapper'dır. WinSW'e göre daha az feature'lı (no `<env>` injection, no XML-driven config) ama hızlı POC için iyi.

```powershell
# 1) NSSM indir (https://nssm.cc/download)
$nssm = "C:\Tools\nssm.exe"

# 2) GUI ile interactive ekran
& $nssm install mersel-dss-signer
#   Application path : java
#   Arguments        : -Xms256m -Xmx1g -jar "C:\Program Files\mersel-dss-signer\mersel-dss-signer-api.jar"
#   Startup directory: C:\Program Files\mersel-dss-signer
#   I/O tab          : stdout / stderr → logs\nssm-out.log, logs\nssm-err.log
#   Environment tab  : CERTIFICATE_PIN, PFX_PATH, ...

# 3) Otomatik başlatma
& $nssm set mersel-dss-signer Start SERVICE_AUTO_START
& $nssm set mersel-dss-signer AppRestartDelay 10000
& $nssm set mersel-dss-signer AppExit Default Restart

# 4) Başlat
Start-Service mersel-dss-signer
```

> **Production önerisi**: WinSW kullan. XML versiyonlanır, env injection script ile audit-trail'e girer; NSSM ise registry-only yapılandırma tutar, "neyin canlıda olduğunu" görmek için `nssm get` ile her property'yi tek tek sorgulamak gerekir.

---

## 7. Operasyon Komutları

```powershell
# Durum
Get-Service mersel-dss-signer
sc.exe query mersel-dss-signer

# Detaylı durum (WinSW)
& "C:\Program Files\mersel-dss-signer\mersel-dss-signer.exe" status

# Restart
Restart-Service mersel-dss-signer

# Stop / Start
Stop-Service mersel-dss-signer
Start-Service mersel-dss-signer

# Logları izle (real-time)
Get-Content "C:\Program Files\mersel-dss-signer\logs\mersel-dss-signer.out.log" `
            -Wait -Tail 50

# Son 200 satır
Get-Content "C:\Program Files\mersel-dss-signer\logs\mersel-dss-signer.out.log" `
            -Tail 200

# Event Viewer'da görüntüle
Get-EventLog -LogName Application -Source "mersel-dss-signer" -Newest 50

# Env değişikliği yaptın → Install scriptini yeniden çalıştır:
.\Install-Service.ps1
```

---

## 8. PFX vs HSM Senaryoları

### PFX (Yumuşak Keystore)

PFX'i `C:\ProgramData\mersel-dss-signer\certs\` altına koy ve NTFS ACL ile kilitle:

```powershell
$pfx = "C:\ProgramData\mersel-dss-signer\certs\production.pfx"
$dir = Split-Path -Parent $pfx
New-Item -Path $dir -ItemType Directory -Force
Copy-Item .\production.pfx $pfx

# Sadece SYSTEM + Administrators
icacls $pfx /inheritance:r `
            /grant:r "NT AUTHORITY\SYSTEM:F" `
            /grant:r "BUILTIN\Administrators:F"
```

Env dosyasında:

```ini
PFX_PATH=C:\ProgramData\mersel-dss-signer\certs\production.pfx
CERTIFICATE_PIN=__GERCEK_PAROLA__
CERTIFICATE_ALIAS=1
```

### HSM (AKİS Windows)

**Kritik 32-bit/64-bit uyumu**: 64-bit JVM kullanıyorsan `akisp11.dll` da 64-bit olmalı. KamuSM resmi installer x86 (32-bit) DLL kurabilir; bu durumda 64-bit JVM `UnsatisfiedLinkError` atar. Çözüm:

```powershell
# JVM 64-bit mi?
java -d64 -version
# Çıktıda "64-Bit" görmeli

# DLL bit-genişliği
[System.Reflection.AssemblyName]::GetAssemblyName("C:\Windows\System32\akisp11.dll").ProcessorArchitecture
# veya  dumpbin /headers C:\Windows\System32\akisp11.dll | findstr machine
```

Smart card servisi:

```powershell
Get-Service SCardSvr
# Status: Running olmalı (WinSW XML'inde Depend tanımlı)

# Kart algılama
certutil -scinfo
```

Env dosyasında:

```ini
PKCS11_LIBRARY=C:\Windows\System32\akisp11.dll
PKCS11_SLOT=-1
PKCS11_SLOT_LIST_INDEX=-1
PKCS11_NULL_INIT_ARGS=false
CERTIFICATE_PIN=__KART_PIN__
```

---

## 9. Güvenlik (NTFS ACL, Service Account)

### XML dosyası

`Install-Service.ps1` XML'e restrictive ACL uygular — sadece **SYSTEM + Administrators** okuyabilir. Doğrula:

```powershell
icacls "C:\Program Files\mersel-dss-signer\mersel-dss-signer.xml"
# Çıktıda Users veya Everyone GÖRÜNMEMELİ
```

### Service Account (önerilen)

Default'ta servis `LocalSystem` olarak çalışır (yüksek yetki). Production'da **dedicated low-privilege account** kullan:

```powershell
# 1) Local user oluştur (veya Domain'de AD account)
$secPwd = Read-Host -AsSecureString "svc_mersel_signer parolası"
New-LocalUser -Name "svc_mersel_signer" `
              -Password $secPwd `
              -Description "Mersel DSS Signer servis hesabı" `
              -PasswordNeverExpires `
              -UserMayNotChangePassword

# 2) "Log on as a service" hakkı ver
# Local Security Policy → Local Policies → User Rights Assignment →
# "Log on as a service" → Add User → svc_mersel_signer
# (Veya `secedit` ile programatik olarak — uzun, atlıyoruz)

# 3) Servisi bu hesapla kur
$secPwd2 = Read-Host -AsSecureString "svc_mersel_signer parolası (tekrar)"
.\Install-Service.ps1 -ServiceAccount ".\svc_mersel_signer" `
                      -ServicePassword $secPwd2

# 4) İzinler — service account log + cert dizinine yazabilsin
icacls "C:\Program Files\mersel-dss-signer\logs" `
       /grant ".\svc_mersel_signer:(OI)(CI)M"
icacls "C:\ProgramData\mersel-dss-signer\certs" `
       /grant ".\svc_mersel_signer:R"
```

### Windows Firewall

Sign API'yi sadece localhost'tan kabul etmek için (reverse proxy önde):

```powershell
New-NetFirewallRule -DisplayName "Mersel DSS Signer (localhost only)" `
                    -Direction Inbound -Protocol TCP `
                    -LocalPort 8085 -RemoteAddress 127.0.0.1,::1 `
                    -Action Allow

# Outbound default allow — KamuSM TSP/OCSP/AIA için açık kalır
```

---

## 10. Reverse Proxy (IIS / nginx) Önerisi

Spring Boot'un built-in Tomcat'ini doğrudan dış dünyaya açmak yerine bir reverse proxy arkasına alın.

### IIS (Windows Server'da default)

URL Rewrite + ARR (Application Request Routing) modüllerini kur, sonra `web.config`:

```xml
<configuration>
  <system.webServer>
    <rewrite>
      <rules>
        <rule name="ReverseProxyToSigner" stopProcessing="true">
          <match url="(.*)" />
          <action type="Rewrite" url="http://localhost:8085/{R:1}" />
        </rule>
      </rules>
    </rewrite>
    <security>
      <requestFiltering>
        <!-- application.properties default'u 200 MB -->
        <requestLimits maxAllowedContentLength="209715200" />
      </requestFiltering>
    </security>
    <httpProtocol>
      <customHeaders>
        <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
```

### nginx (Linux subsystem veya container)

Bkz. [SystemD README — Reverse Proxy bölümü](../systemd/README.md#8-reverse-proxy-nginx-önerisi).

---

## 11. Sorun Giderme

### Servis kalkmıyor — Event Viewer

```powershell
# Event Viewer → Windows Logs → Application
Get-EventLog -LogName Application -Source "mersel-dss-signer" -Newest 20 |
    Format-List Source, EventID, Message
```

WinSW log dosyaları:

```powershell
$logDir = "C:\Program Files\mersel-dss-signer\logs"
Get-ChildItem $logDir
# mersel-dss-signer.out.log         → stdout (Spring Boot)
# mersel-dss-signer.err.log         → stderr
# mersel-dss-signer.wrapper.log     → WinSW kendi log'u
```

### "java is not recognized"

`java` PATH'te değil. Çözüm: `Install-Service.ps1 -JavaHome` ile tam yol ver:

```powershell
.\Install-Service.ps1 -JavaHome "C:\Program Files\Eclipse Adoptium\jdk-8.0.412.8-hotspot"
```

### Servis sürekli restart oluyor (crash loop)

`Get-Service` "Running" → "Stopped" arası geziyor. WinSW XML'de `<onfailure action="restart">` üç kez denedikten sonra durur.

```powershell
# Wrapper log'unda crash sebebini ara
Get-Content "C:\Program Files\mersel-dss-signer\logs\mersel-dss-signer.wrapper.log" -Tail 100
# "Java application has exited with code N" → exit code Spring Boot hatası
```

Genelde:
- `CERTIFICATE_PIN` yanlış — PFX/HSM yetkilendirme ekranı
- `PKCS11_LIBRARY` yolu yanlış — DLL bulunamadı
- Port 8085 başka süreç tarafından tutuluyor — `Get-NetTCPConnection -LocalPort 8085`

### "UnsatisfiedLinkError" — PKCS#11

64-bit / 32-bit uyumsuzluğu. Bkz. [Bölüm 8 — HSM](#8-pfx-vs-hsm-senaryoları).

### Env değişikliği uygulanmıyor

`mersel-dss-signer.env`'i değiştirip `Restart-Service` yetmez — XML'e inject edilmiş hâli yeniden üretmek gerekir:

```powershell
# Install scriptini yeniden çalıştır
.\Install-Service.ps1
# script servisi durdurur, XML'i yenisiyle değiştirir, yeniden başlatır
```

### Smart card görünmüyor

```powershell
# PC/SC servisi
Get-Service SCardSvr
Restart-Service SCardSvr

# Kart okuyucu listesi
certutil -scinfo

# Sürücü tanımlı mı?
Get-PnpDevice -Class SmartCardReader
```

---

## 12. Kaldırma

```powershell
# Default — install dizini silinir, ProgramData korunur
.\Uninstall-Service.ps1

# Logları post-mortem için %TEMP%'e yedekle
.\Uninstall-Service.ps1 -KeepLogs

# Komple temizlik — env + cert dizini DAHİL
.\Uninstall-Service.ps1 -Purge
```

---

## İlgili Dokümanlar

- [docs/RUN_PROFILES.md](../../docs/RUN_PROFILES.md) — Spring profile mimarisi
- [devops/systemd/](../systemd/) — Linux SystemD muadili
- [devops/docker/](../docker/) — Docker deployment (Linux container'da hızlı PoC)
- [devops/monitoring/](../monitoring/) — Prometheus + Grafana
- [WinSW resmi dokümanı](https://github.com/winsw/winsw/blob/master/docs/xml-config-file.md)
- [NSSM resmi dokümanı](https://nssm.cc/usage)
- [Ana dokümantasyon](https://dss.mersel.dev)
