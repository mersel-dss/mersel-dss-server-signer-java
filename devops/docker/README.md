# 🐳 Docker Deployment

Sign API Docker yapılandırma dosyaları.

## 📁 İçerik

```
devops/docker/
├── Dockerfile              # Docker image definition
├── docker-compose.yml      # Monitoring stack
├── .dockerignore          # Build optimization
├── .env.example           # Production template
├── .env.test.kurum1       # Test Kurum 1
├── .env -> .env.test.kurum1  # Symlink
├── unix/                  # Unix helper scripts
│   ├── start-test-kurum1.sh
│   ├── start-test-kurum2.sh
│   └── start-test-kurum3.sh
├── windows/               # Windows helper scripts
│   ├── start-test-kurum1.ps1
│   ├── start-test-kurum2.ps1
│   └── start-test-kurum3.ps1
└── README.md
```

## 🚀 Hızlı Başlangıç

### Test Kurumu ile (EN HIZLI!)

```bash
# Bu dizine git
cd devops/docker

# Direkt başlat (varsayılan: Test Kurum 1)
docker-compose up -d
```

Varsayılan olarak `.env.test.kurum1` kullanılır (symlink).

### Farklı Test Kurumu

```bash
# Test Kurum 2 ile
docker-compose --env-file .env.test.kurum2 up -d

# Test Kurum 3 ile
docker-compose --env-file .env.test.kurum3 up -d
```

### Production için

```bash
# .env.example'dan kendi .env'ini oluştur
cp .env.example .env.production
nano .env.production

# Production ile başlat
docker-compose --env-file .env.production up -d
```

## 🌐 Endpoint'ler

- **Sign API:** http://localhost:8085
- **Health Check:** http://localhost:8085/actuator/health
- **Prometheus:** http://localhost:9090
- **Grafana:** http://localhost:3000 (admin/admin)

## 📊 Grafana Dashboard

**Dashboard ID: 11378** (Spring Boot 2.x)

Import adımları:
1. http://localhost:3000 → Login (admin/admin)
2. `+` → `Import` → `11378`
3. Prometheus data source seç → Import

## 📋 Test Kurumları

Hazır test yapılandırmaları:

| Env Dosyası | Sertifika | Parola | Helper Scripts |
|-------------|-----------|--------|----------------|
| `.env.test.kurum1` | testkurum01@test.com.tr | 614573 | `start-test-kurum1` |
| `.env.test.kurum2` | testkurum02@sm.gov.tr | 059025 | `start-test-kurum2` |
| `.env.test.kurum3` | testkurum3@test.com.tr | 181193 | `start-test-kurum3` |

> **Not:** Her script için .sh (Unix) ve .ps1 (Windows) versiyonu mevcut

### Hızlı Başlatma Script'leri

**Unix/Linux/macOS:**
```bash
./unix/start-test-kurum1.sh
./unix/start-test-kurum2.sh
./unix/start-test-kurum3.sh
```

**Windows (PowerShell):**
```powershell
.\windows\start-test-kurum1.ps1
.\windows\start-test-kurum2.ps1
.\windows\start-test-kurum3.ps1
```

## 🔧 Servisler

### Sign API

```bash
# Varsayılan (.env.test.kurum1)
docker-compose up -d sign-api

# Belirli test kurumu ile
docker-compose --env-file .env.test.kurum2 up -d sign-api

# Log'ları izle
docker-compose logs -f sign-api

# Restart
docker-compose restart sign-api
```

### Monitoring Stack

```bash
# Prometheus + Grafana
docker-compose up -d

# AlertManager dahil
docker-compose --profile monitoring-full up -d
```

## 📚 Detaylı Döküman

Tüm detaylar için: [Docker Deployment](https://dss.mersel.dev/devops/docker)

---

**Kolay deployment için Docker!** 🐳

