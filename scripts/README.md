# 🛠️ Scripts Klasörü

Bu klasörde Sign API için yardımcı script'ler bulunmaktadır.

## 📁 Klasör Yapısı

```
scripts/
├── unix/              # Unix/Linux/macOS script'leri (.sh)
│   ├── quick-start-with-test-certs.sh
│   ├── start-test1.sh
│   ├── start-test2.sh
│   ├── start-test3.sh
│   ├── test-with-bundled-certs.sh
│   └── README.md
├── windows/           # Windows script'leri (.ps1)
│   ├── quick-start-with-test-certs.ps1
│   ├── start-test1.ps1
│   ├── start-test2.ps1
│   ├── start-test3.ps1
│   └── README.md
├── prepare-github-release.sh
└── README.md          # Bu dosya
```

## 🖥️ Platform Desteği

| Platform | Script Tipi | Konum |
|----------|-------------|-------|
| **Unix/Linux/macOS** | Bash (.sh) | `scripts/unix/` |
| **Windows** | PowerShell (.ps1) | `scripts/windows/` |

## 📁 İçerik

### 🔐 Test Sertifikaları ile Başlatma

#### Unix/Linux/macOS

| Script | Açıklama |
|--------|----------|
| `unix/quick-start-with-test-certs.sh` | İnteraktif sertifika seçimi ve otomatik başlatma |
| `unix/start-test1.sh` | Test Sertifikası 1 ile direkt başlatma |
| `unix/start-test2.sh` | Test Sertifikası 2 ile direkt başlatma |
| `unix/start-test3.sh` | Test Sertifikası 3 ile direkt başlatma |
| `unix/test-with-bundled-certs.sh` | Tüm API endpoint'lerini otomatik test eder |

#### Windows

| Script | Açıklama |
|--------|----------|
| `windows/quick-start-with-test-certs.ps1` | İnteraktif başlatma |
| `windows/start-test1.ps1` | Test Sertifikası 1 |
| `windows/start-test2.ps1` | Test Sertifikası 2 |
| `windows/start-test3.ps1` | Test Sertifikası 3 |

### 🚀 Diğer

| Script | Açıklama |
|--------|----------|
| `prepare-github-release.sh` | GitHub release hazırlama |

## 🚀 Hızlı Kullanım

### Unix/Linux/macOS

```bash
# İnteraktif başlatma (önerilen)
./scripts/unix/quick-start-with-test-certs.sh

# Direkt başlatma
./scripts/unix/start-test1.sh
./scripts/unix/start-test2.sh
./scripts/unix/start-test3.sh

# API testleri
./scripts/unix/test-with-bundled-certs.sh
```

### Windows (PowerShell)

```powershell
# İnteraktif başlatma (önerilen)
.\scripts\windows\quick-start-with-test-certs.ps1

# Direkt başlatma
.\scripts\windows\start-test1.ps1
.\scripts\windows\start-test2.ps1
.\scripts\windows\start-test3.ps1
```


## 📖 Test Sertifikaları

Repo içinde kullanıma hazır 3 test sertifikası bulunmaktadır:

| Sertifika | Parola | Konum |
|-----------|--------|-------|
| `testkurum01@test.com.tr_614573.pfx` | `614573` | `resources/test-certs/` |
| `testkurum02@sm.gov.tr_059025.pfx` | `059025` | `resources/test-certs/` |
| `testkurum3@test.com.tr_181193.pfx` | `181193` | `resources/test-certs/` |

> 💡 **İpucu:** Dosya adında `_` karakterinden sonraki kısım paroladır.

## 🔄 Script Çalışma Mantığı

Tüm test sertifika script'leri:
1. Otomatik olarak proje root dizinine `cd` yapar
2. Gerekli environment variables'ları ayarlar
3. Maven ile uygulamayı başlatır

Bu sayede script'leri nereden çağırırsanız çağırın doğru çalışırlar:

```bash
# Root dizinden
./scripts/start-test1.sh

# Scripts dizininden
cd scripts && ./start-test1.sh

# Başka bir dizinden
/full/path/to/scripts/start-test1.sh
```

## 📚 Detaylı Dökümanlar

- **[TEST_CERTIFICATES.md](../TEST_CERTIFICATES.md)** - Kapsamlı test sertifikaları rehberi
- **[TEST_CERTS_CHEATSHEET.md](../TEST_CERTS_CHEATSHEET.md)** - Hızlı başvuru kılavuzu
- **[Hızlı Başlangıç](https://dss.mersel.dev/getting-started/quick-start)** - Genel hızlı başlangıç
- **[Ana Dokümantasyon](https://dss.mersel.dev)** - Merkezi dokümantasyon

## 💡 İpuçları

### Farklı Port ile Başlatma

```bash
export SERVER_PORT=9090
./scripts/start-test1.sh
```

### Debug Mode

```bash
export LOGGING_LEVEL_ROOT=DEBUG
./scripts/start-test1.sh
```

### TÜBİTAK Timestamp ile

```bash
# İnteraktif script içinde seçebilirsiniz
./scripts/quick-start-with-test-certs.sh

# Veya manuel
export IS_TUBITAK_TSP=true
export TS_USER_ID=your-id
export TS_USER_PASSWORD=your-password
./scripts/start-test1.sh
```

## 🛠️ Yeni Script Ekleme

Bu klasöre yeni script eklerken:

1. Script'i çalıştırılabilir yapın: `chmod +x script-name.sh`
2. Proje root'una cd yapmayı unutmayın: `cd "$(dirname "$0")/.."`
3. Bu README'yi güncelleyin
4. İlgili dökümanları güncelleyin

Örnek script başlangıcı:

```bash
#!/bin/bash
# Script açıklaması

set -e

# Proje root dizinine git
cd "$(dirname "$0")/.." || exit 1

# Script kodunuz...
```

## 🔧 Sorun Giderme

### "Permission denied"

```bash
chmod +x scripts/*.sh
```

### "No such file or directory"

Script'leri proje root dizininden çalıştırın veya tam yol kullanın.

### "PFX dosyası bulunamadı"

Test sertifikalarının `resources/` veya `src/main/resources/certs/` klasörlerinde olduğundan emin olun.

---

**Daha fazla yardım için:** [TEST_CERTIFICATES.md](../TEST_CERTIFICATES.md)

