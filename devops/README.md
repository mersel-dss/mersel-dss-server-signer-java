# 🚀 DevOps Klasörü

Bu klasörde Sign API için deployment ve operasyon dosyaları bulunmaktadır.

## 📁 Klasör Yapısı

```
devops/
├── docker/                 # Docker deployment
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── .dockerignore
│   ├── .env.example       # Production template
│   ├── .env.test.kurum1   # Test Kurum 1
│   ├── .env -> .env.test.kurum1  # Symlink
│   ├── unix/              # Unix helper scripts
│   │   ├── start-test-kurum1.sh
│   │   ├── start-test-kurum2.sh
│   │   └── start-test-kurum3.sh
│   ├── windows/           # Windows helper scripts
│   │   ├── start-test-kurum1.ps1
│   │   ├── start-test-kurum2.ps1
│   │   └── start-test-kurum3.ps1
│   └── README.md
├── monitoring/            # Monitoring stack configurations
│   ├── prometheus/
│   │   ├── prometheus.yml
│   │   └── alerts.yml
│   ├── grafana/
│   │   ├── provisioning/
│   │   └── dashboards/
│   └── alertmanager/
│       └── alertmanager.yml
└── kubernetes/            # Kubernetes manifests (gelecek)
    └── README.md
```

## 🐳 Docker

### Hızlı Başlangıç

**Test Sertifikaları ile:**

```bash
# Docker dizinine git
cd devops/docker

# Unix/Linux/macOS
./unix/start-test-kurum1.sh

# Windows
.\windows\start-test-kurum1.ps1

# veya direkt
docker-compose up -d  # Varsayılan: .env.test.kurum1
```

**Production için:**

```bash
cd devops/docker

# .env dosyasını düzenle
cp .env.example .env
nano .env

# Başlat
docker-compose up -d
```

**Detaylı bilgi:** [Docker](https://dss.mersel.dev/devops/docker)

### Kullanılabilir Komutlar

```bash
# Monitoring stack ile başlat
docker-compose up -d

# Sadece Sign API
docker-compose up -d sign-api

# Log'ları izle
docker-compose logs -f sign-api

# Durdur
docker-compose down

# Temizle (volumes dahil)
docker-compose down -v
```

## 📊 Monitoring

### Prometheus

**URL:** http://localhost:9090

**Yapılandırma:**
- Scrape interval: 15s
- Retention: 90 gün
- Alert rules: 8 kural

### Grafana

**URL:** http://localhost:3000  
**Varsayılan:** admin / admin

**Önerilen Dashboard ID: 11378** (Spring Boot 2.x)

### AlertManager

**URL:** http://localhost:9093

Aktif etmek için:
```bash
docker-compose --profile monitoring-full up -d
```

## ☸️ Kubernetes

> 🚧 **Yakında:** Kubernetes manifest'leri v0.2.0'da eklenecek

Planlanan özellikler:
- Deployment manifests
- Service definitions
- ConfigMaps & Secrets
- Ingress configuration
- HPA (Horizontal Pod Autoscaler)
- PersistentVolumeClaims

## 🔧 Yapılandırma

### Environment Variables

`.env` dosyasında ayarlanabilir:

```bash
# Sertifika
CERTIFICATE_PIN=your-password
CERTIFICATE_ALIAS=1

# Timestamp
IS_TUBITAK_TSP=true
TS_USER_ID=your-id
TS_USER_PASSWORD=your-password

# Grafana
GRAFANA_PASSWORD=secure-password
```

### Secrets Yönetimi

Production'da:
```bash
# Docker secrets kullan
echo "your-password" | docker secret create cert_pin -

# docker-compose.yml'de:
# secrets:
#   - cert_pin
```

## 📚 İlgili Dökümanlar

- [Docker](https://dss.mersel.dev/devops/docker) - Docker kullanım rehberi
- [Monitoring](https://dss.mersel.dev/sign-api/monitoring) - Prometheus & Grafana detayları
- [Actuator Endpoints](https://dss.mersel.dev/sign-api/actuator-endpoints) - Health checks
- [Ana Dokümantasyon](https://dss.mersel.dev) - Merkezi dokümantasyon

## 🎯 Örnek Kullanım

### Development

```bash
cd devops/docker
docker-compose up -d
```

### Production

```bash
cd devops/docker

# .env ile production ayarları
cat > .env << EOF
CERTIFICATE_PIN=${PROD_CERT_PIN}
CERTIFICATE_ALIAS=production-cert
IS_TUBITAK_TSP=true
TS_USER_ID=${PROD_TS_USER}
TS_USER_PASSWORD=${PROD_TS_PASS}
GRAFANA_PASSWORD=${SECURE_GRAFANA_PASS}
EOF

# Başlat
docker-compose up -d
```

---

**🚀 Modern DevOps practices ile kolay deployment!**

