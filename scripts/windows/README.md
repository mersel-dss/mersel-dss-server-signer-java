# 🪟 Windows Script'leri

Sign API için Windows uyumlu script'ler.

## 📋 İçerik

### PowerShell Script'leri (.ps1)

| Script | Açıklama |
|--------|----------|
| `quick-start-with-test-certs.ps1` | İnteraktif sertifika seçimi ve başlatma |
| `start-test1.ps1` | Test Sertifikası 1 ile başlat |
| `start-test2.ps1` | Test Sertifikası 2 ile başlat |
| `start-test3.ps1` | Test Sertifikası 3 ile başlat |

## 🚀 Kullanım

### PowerShell ile

```powershell
# PowerShell'i açın (yönetici olması gerekmez)

# Execution policy ayarlayın (ilk kez)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Script'i çalıştırın
cd path\to\sign-api
.\scripts\windows\quick-start-with-test-certs.ps1

# veya direkt başlatma
.\scripts\windows\start-test1.ps1
```

## ⚙️ Gereksinimler

### Java

```cmd
# Java versiyonunu kontrol edin
java -version

# JDK 8 veya üzeri gerekli
```

### Maven

```cmd
# Maven versiyonunu kontrol edin
mvn -version

# Maven yoksa:
# https://maven.apache.org/download.cgi
```

### PowerShell (Windows 10/11'de yerleşik)

```powershell
# PowerShell versiyonu
$PSVersionTable.PSVersion

# 5.1 veya üzeri önerilir
```

## 🔍 Test Sertifikaları

| Sertifika | Parola | Konum |
|-----------|--------|-------|
| `testkurum01@test.com.tr_614573.pfx` | `614573` | `resources\test-certs\` |
| `testkurum02@sm.gov.tr_059025.pfx` | `059025` | `resources\test-certs\` |
| `testkurum3@test.com.tr_181193.pfx` | `181193` | `resources\test-certs\` |

## 🧪 Test Komutları

### API Test (PowerShell)

```powershell
# Test XML oluştur
@"
<?xml version="1.0"?>
<test>data</test>
"@ | Out-File -Encoding UTF8 test.xml

# İmzala
Invoke-RestMethod -Method Post -Uri "http://localhost:8085/v1/xadessign" `
  -Form @{
    document = Get-Item "test.xml"
    documentType = "None"
  } `
  -OutFile "signed-test.xml"

# Sonucu görüntüle
Get-Content signed-test.xml
```

### API Test (curl - Git Bash / WSL)

```bash
# curl ile (Git Bash veya WSL'de)
curl -X POST http://localhost:8085/v1/xadessign \
  -F "document=@test.xml" \
  -F "documentType=None" \
  -o signed-test.xml
```

## 🐛 Sorun Giderme

### "Execution Policy" Hatası

```powershell
# PowerShell execution policy ayarla
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# veya script'i bypass ile çalıştır
powershell -ExecutionPolicy Bypass -File .\scripts\windows\start-test1.ps1
```

### "Maven bulunamadı" Hatası

```cmd
# Maven'in PATH'de olduğunu kontrol edin
where mvn

# Yoksa PATH'e ekleyin:
# Sistem → Gelişmiş sistem ayarları → Ortam Değişkenleri
# Path değişkenine Maven\bin dizinini ekleyin
```

### "PFX dosyası bulunamadı"

```powershell
# Dosyanın varlığını kontrol edin
Test-Path ".\resources\test-certs\testkurum01@test.com.tr_614573.pfx"

# Klasör yapısını kontrol edin
Get-ChildItem -Recurse -Filter "*.pfx"
```

### "Port already in use"

```powershell
# Port'u kim kullanıyor?
Get-NetTCPConnection -LocalPort 8085

# Process'i sonlandır
Stop-Process -Id <PID>

# veya farklı port kullan
$env:SERVER_PORT = "8086"
mvn spring-boot:run
```

## 💡 İpuçları

### 1. PowerShell Profile

Sık kullanılan komutları PowerShell profile'a ekleyin:

```powershell
# Profile'ı açın
notepad $PROFILE

# Ekleyin:
function Start-SignAPI {
    param([int]$CertNumber = 1)
    cd "C:\path\to\sign-api"
    .\scripts\windows\start-test$CertNumber.ps1
}

# Kullanım:
Start-SignAPI -CertNumber 1
```

### 2. Environment Variables Persist

```powershell
# System-wide environment variable (yönetici gerekir)
[Environment]::SetEnvironmentVariable("CERTIFICATE_PIN", "your-pin", "Machine")

# User-level environment variable
[Environment]::SetEnvironmentVariable("CERTIFICATE_PIN", "your-pin", "User")
```

### 3. Alias Kullanımı

```powershell
# PowerShell alias
Set-Alias -Name signapi -Value "C:\path\to\sign-api\scripts\windows\start-test1.ps1"

# Kullanım
signapi
```

## 🔄 Unix Script'leri Karşılaştırması

| Unix (Bash) | Windows (PowerShell) |
|-------------|---------------------|
| `scripts/unix/*.sh` | `scripts/windows/*.ps1` |
| `chmod +x script.sh` | `Set-ExecutionPolicy` |
| `./script.sh` | `.\script.ps1` |
| `export VAR=value` | `$env:VAR = "value"` |

## 📚 Ek Kaynaklar

- [PowerShell Dökümanı](https://docs.microsoft.com/powershell/)
- [Unix Script'leri](../unix/README.md)
- [Docker Guide](https://dss.mersel.dev/devops/docker)

---

**Not:** Modern Windows için PowerShell önerilir. Windows 10/11'de yerleşik olarak gelir.

