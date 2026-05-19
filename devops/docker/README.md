# Docker Deployment

Mersel DSS Signer API'nin container imajı ve compose stack'i.

## İçerik

```
devops/docker/
├── Dockerfile                       # Production multi-stage (maven build → JRE 8 runtime)
├── Dockerfile.pkcs11-tests          # Integration test image (softhsm2 + opensc + JDK)
├── docker-compose.yml               # sign-api + prometheus + grafana (+ alertmanager profile)
├── .dockerignore
├── .env.example                     # Production env şablonu
├── .env.test.kurum1                 # Test Kurum 1 (RSA-2048, PIN 614573)
├── .env -> .env.test.kurum1         # Symlink → default development env
├── unix/start-test-kurum.sh         # Parametreli helper (./start-test-kurum.sh 2 ec384)
├── windows/start-test-kurum.ps1     # PowerShell muadili
└── README.md
```

> **Not**: Mevcut dosya tek parametreli helper script'tir (kurum_no + cert_type). Eski README'deki `start-test-kurum1.sh`, `start-test-kurum2.sh` gibi ayrı dosyalar konsolide edildi.

---

## Hızlı Başlangıç

### En hızlı yol — varsayılan test sertifikası

```bash
cd devops/docker
docker-compose up -d
```

Varsayılan olarak `.env -> .env.test.kurum1` symlink'i devreye girer (RSA-2048 test PFX, network kapalı).

### Parametreli helper ile farklı kurum / algoritma

```bash
# Unix/Linux/macOS
./unix/start-test-kurum.sh 1                  # Kurum 1 RSA-2048 (default)
./unix/start-test-kurum.sh 2 rsa              # Kurum 2 RSA-2048
./unix/start-test-kurum.sh 2 ec384            # Kurum 2 EC-P384
./unix/start-test-kurum.sh 3 rsa              # Kurum 3 RSA-2048
./unix/start-test-kurum.sh 3 ec384            # Kurum 3 EC-P384

# Windows (PowerShell)
.\windows\start-test-kurum.ps1 1
.\windows\start-test-kurum.ps1 2 ec384
.\windows\start-test-kurum.ps1 3 rsa
```

Script `.env.temp` üretir ve `docker-compose --env-file .env.temp up -d` çağırır. Compose'un kendi env dosyasını kirletmez.

### Production

```bash
# .env.example'dan kendi env dosyanı oluştur
cp .env.example .env.production
nano .env.production  # PFX_PATH, CERTIFICATE_PIN, TS_USER_*, vb.

# Production env ile başlat
docker-compose --env-file .env.production up -d
```

PFX dosyasını volumed olarak içeri al:

```yaml
# docker-compose.yml içinde
volumes:
  - /etc/mersel-dss-signer/certs:/app/certs:ro
```

> **Production önerisi**: Bare-metal Linux'ta SystemD ile çalışmak smart card / AKİS HSM senaryolarında daha az operasyonel acı verir. Bkz. [`devops/systemd/`](../systemd/).

---

## Endpoint'ler

| Servis | URL | Default kimlik |
|---|---|---|
| Sign API | http://localhost:8085 | — |
| Health  | http://localhost:8085/actuator/health | — |
| Prometheus metrics | http://localhost:8085/actuator/prometheus | — |
| OpenAPI JSON | http://localhost:8085/api-docs | — |
| Prometheus UI | http://localhost:9090 | — |
| Grafana | http://localhost:3000 | `admin` / `admin` |
| AlertManager | http://localhost:9093 (`--profile monitoring-full`) | — |

---

## Test Sertifikaları (repo içi)

| Kurum | Algoritma | PFX | PIN |
|---|---|---|---|
| Kurum 1 | RSA-2048 | `testkurum01_rsa2048@test.com.tr_614573.pfx` | `614573` |
| Kurum 2 | RSA-2048 | `testkurum02_rsa2048@sm.gov.tr_059025.pfx` | `059025` |
| Kurum 2 | EC-P384 | `testkurum02_ec384@test.com.tr_825095.pfx` | `825095` |
| Kurum 3 | RSA-2048 | `testkurum03_rsa2048@test.com.tr_181193.pfx` | `181193` |
| Kurum 3 | EC-P384 | `testkurum03_ec384@test.com.tr_540425.pfx` | `540425` |

Yerleşim: `resources/test-certs/` — Dockerfile build-time'da `/app/test-certs/` altına kopyalar (development image için). Production'da kendi PFX'inizi bind-mount edersiniz.

---

## Compose Profile'ları

```bash
# Default: sign-api + prometheus + grafana
docker-compose up -d

# AlertManager dahil
docker-compose --profile monitoring-full up -d

# Sadece sign-api (prometheus/grafana olmadan)
docker-compose up -d sign-api
```

---

## Operasyon Komutları

```bash
# Loglar
docker-compose logs -f sign-api

# Status
docker-compose ps

# Restart
docker-compose restart sign-api

# Tek servisin env'ini gör
docker-compose exec sign-api env | grep -E "(PFX|PKCS11|TS_)"

# Container'ın içine gir
docker-compose exec sign-api sh

# Container'da Java thread dump (deadlock şüphesi için)
docker-compose exec sign-api sh -c 'kill -3 1; sleep 1; cat /proc/1/fd/1' | head -200

# Cleanup
docker-compose down            # container + network
docker-compose down -v         # YUKARI + volume'ler (Prometheus retention dahil)
docker-compose down --rmi all  # YUKARI + image'ler
```

---

## Image Build

```bash
# Standart build
docker-compose build sign-api

# No-cache (dependency güncellemesi sonrası)
docker-compose build --no-cache sign-api

# Multi-arch (CI gibi)
docker buildx build \
    --platform linux/amd64,linux/arm64 \
    -t mersel/dss-signer-api:0.4.0 \
    -f devops/docker/Dockerfile \
    ../..
```

`Dockerfile` iki-aşamalı: `maven:3.8-openjdk-8` ile build, `eclipse-temurin:8-jre` ile runtime. Runtime image yaklaşık 250 MB, fat-jar 60-80 MB.

---

## Production Hardening Önerileri

```yaml
# docker-compose.yml içinde sign-api servisine ekle
services:
  sign-api:
    read_only: true
    tmpfs:
      - /tmp
      - /app/logs:size=512m
    cap_drop: [ALL]
    cap_add:
      - NET_BIND_SERVICE  # 8085 < 1024 değilse gereksiz
    security_opt:
      - no-new-privileges:true
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          memory: 512M
```

> AKİS HSM senaryosunda `read_only: true` ile PC/SC socket'i uyumlu çalışabilir; ama smart card için zaten bind-mount + `privileged: true` gerektiğinden container yaklaşımı önerilmez.

---

## Sorun Giderme

```bash
# Container kalkmıyor — exit code'a bak
docker-compose ps -a
docker-compose logs sign-api | tail -100

# "exec format error" — multi-arch mismatch
docker inspect sign-api --format '{{.Config.Image}} {{.Image}}'
# arm64 host'ta amd64 image: docker pull --platform linux/arm64/v8 ...

# Spring Boot kalkmadı — health check 60sn start_period bekler
docker-compose logs sign-api 2>&1 | grep -i "started\|error"

# Network sorunu — sign-api ↔ prometheus
docker-compose exec prometheus wget -qO- http://sign-api:8085/actuator/prometheus | head

# Volume yetki sorunu (özellikle Linux host'ta)
docker-compose exec sign-api ls -la /app/certs /app/logs
# UID 1000 (signapi) yazabiliyor mu?
```

---

## İlgili Dokümanlar

- [`devops/README.md`](../README.md) — Genel deployment matrisi
- [`devops/systemd/`](../systemd/) — Linux native servis (smart card için tercih)
- [`devops/windows-service/`](../windows-service/) — Windows native servis
- [`devops/monitoring/`](../monitoring/) — Prometheus/Grafana detayları
- [`docs/RUN_PROFILES.md`](../../docs/RUN_PROFILES.md) — Spring profile mimarisi
- [Docker Deployment Guide](https://dss.mersel.dev/devops/docker) — Online doc
