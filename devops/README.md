# DevOps

Mersel DSS Signer API'yi farklı ortamlarda (Linux / Windows / Container / K8s) deploy etmek için gerekli tüm yapılandırma dosyaları ve helper script'ler burada toplanmıştır.

## Hızlı Yön

| Senaryo | Klasör | Tek Komut |
|---|---|---|
| **Geliştirici makinesi** (laptop, IDE'siz) | [`docker/`](./docker/) | `docker-compose up -d` |
| **Linux Production** (bare-metal / VM) | [`systemd/`](./systemd/) | `sudo ./devops/systemd/install.sh` |
| **Windows Production** (Server 2019/2022) | [`windows-service/`](./windows-service/) | `.\Install-Service.ps1` (admin PS) |
| **Container Orchestration** | [`kubernetes/`](./kubernetes/) | v0.5.0 — preview manifest |
| **Observability** | [`monitoring/`](./monitoring/) | Docker-compose ile birlikte |

> **Geliştirici modu** — `mvn spring-boot:run` ile profile-based çalıştırmak için bkz. [`docs/RUN_PROFILES.md`](../docs/RUN_PROFILES.md). DevOps klasörü **production deployment**'a odaklıdır; IDE Run Configuration'ları ve `scripts/dev-run.{sh,bat}` ayrı katmandır.

---

## Klasör Yapısı

```
devops/
├── docker/                          # Container deployment
│   ├── Dockerfile                   # Production multi-stage image
│   ├── Dockerfile.pkcs11-tests      # Integration test image (softhsm2 + JDK)
│   ├── docker-compose.yml           # Sign API + Prometheus + Grafana (+ AlertManager profile)
│   ├── .dockerignore
│   ├── .env.example                 # Production env şablonu
│   ├── .env.test.kurum1             # Test Kurum 1 (RSA-2048)
│   ├── .env -> .env.test.kurum1     # Symlink (default)
│   ├── unix/start-test-kurum.sh     # Parametreli helper (./start-test-kurum.sh 2 ec384)
│   ├── windows/start-test-kurum.ps1 # PowerShell muadili
│   └── README.md
│
├── systemd/                         # Linux SystemD servisi (hardened unit)
│   ├── mersel-dss-signer.service    # Unit dosyası
│   ├── mersel-dss-signer.env.example
│   ├── install.sh                   # Otomatik kurulum (user + dizinler + start)
│   ├── uninstall.sh                 # Temiz kaldırma (--purge ile env+log+user)
│   └── README.md
│
├── windows-service/                 # Windows servisi (WinSW + NSSM alt.)
│   ├── mersel-dss-signer.xml        # WinSW XML şablonu
│   ├── mersel-dss-signer.env.example
│   ├── Install-Service.ps1          # Tek-dosyalı kur/kaldır (-Action Install|Uninstall)
│   └── README.md
│
├── monitoring/                      # Observability stack
│   ├── prometheus/                  # prometheus.yml + alerts.yml
│   ├── grafana/                     # Auto-provisioning + dashboards
│   ├── alertmanager/                # Routing & receivers
│   ├── load-test.sh                 # Metric generation için load test
│   └── README.md
│
├── kubernetes/                      # K8s manifests (preview)
│   └── README.md                    # v0.5.0 roadmap
│
└── README.md                        # Bu dosya
```

---

## Deployment Karar Matrisi

| Kriter | Docker Compose | SystemD | Windows Service | Kubernetes |
|---|---|---|---|---|
| **Kurulum süresi** | Dakikalar | Dakikalar | Dakikalar | Saatler (ilk setup) |
| **Native PKCS#11 (smart card)** | Sınırlı (USB passthrough) | ✅ Tam | ✅ Tam | Sınırlı (DaemonSet + privileged) |
| **JIT + JNI performansı** | ✅ Linux native | ✅ Native | ✅ Native | ✅ Pod native |
| **HA / Auto-scale** | Manual | Manual (multiple unit) | Manual | ✅ HPA |
| **Log aggregation** | Docker logs / Loki | journald → rsyslog | Event Viewer | Vector/Fluentd |
| **Operatör profili** | Containerlı senaryolar | klasik sysadmin | Windows admin | platform team |
| **Önerilen kullanım** | Dev + staging | Tek-makine prod, on-prem | Windows-only prod, on-prem | Multi-tenant prod |

**Pratik öneri**:
- Smart card / AKİS HSM kullanıyorsan → **SystemD veya Windows Service** (kart fiziksel olarak makineye takılı, container'a passthrough operasyonel acı).
- Bulut yedeği veya stateless API (PFX-based) → **Docker Compose** veya **Kubernetes**.

---

## Spring Profile vs Env Variable

Uygulama config'i iki kaynaktan beslenir:

1. **`application.properties` + profile** (`application-<profile>.properties`) — repo'da versiyonlanır, **Spring Profile** ile aktive edilir.
2. **Environment variable** — runtime'da operatör tarafından verilir, secret'ları taşır.

Production deployment'larda **`SPRING_PROFILES_ACTIVE` boş bırakılır** (default `application.properties` yüklenir) ve secret'lar (PIN, parola, PKCS#11 yolu) env variable olarak verilir. Test/staging için profile composition kullanılır:

```
SPRING_PROFILES_ACTIVE=local,pfx-kurum01-rsa2048    # PFX test, network off
SPRING_PROFILES_ACTIVE=local,mali-muhur-akis-linux  # Mali Mühür AKİS Linux sürücüsü, network off
```

Detaylı mimari: [`docs/RUN_PROFILES.md`](../docs/RUN_PROFILES.md).

---

## Ortak Env Variable'lar

Aşağıdaki değişkenler **tüm deployment'larda** geçerlidir (kaynak: [`application.properties`](../src/main/resources/application.properties)).

| Kategori | Variable | Default | Açıklama |
|---|---|---|---|
| Server | `SERVER_PORT` | 8085 | HTTP port |
| Logging | `LOG_PATH` | `./logs` | Logback file appender hedefi |
| Logging | `LOG_LEVEL` | `INFO` | Root + uygulama paketi seviyesi |
| **PFX** | `PFX_PATH` | — | PFX dosyasının yolu |
| **PFX** | `CERTIFICATE_PIN` | — | PFX parolası |
| **PFX/HSM** | `CERTIFICATE_ALIAS` | `1` | Alias |
| **HSM** | `PKCS11_LIBRARY` | — | PKCS#11 sürücü yolu (.so / .dylib / .dll) |
| **HSM** | `PKCS11_SLOT` | -1 | Slot ID (-1 = auto) |
| **HSM** | `PKCS11_SLOT_LIST_INDEX` | -1 | Slot list index (-1 = auto) |
| **HSM** | `PKCS11_NULL_INIT_ARGS` | false | `CKR_ARGUMENTS_BAD` fallback için true |
| **TSP** | `IS_TUBITAK_TSP` | (auto) | TÜBİTAK TSP modu — host'tan tespit edilir |
| **TSP** | `TS_SERVER_HOST` | — | TSP endpoint URL |
| **TSP** | `TS_USER_ID` / `TS_USER_PASSWORD` | — | TÜBİTAK abone bilgileri |
| **XAdES** | `XADES_SIGNING_TIME_ZONE` | `+03:00` | SigningTime timezone ([issue #7](https://github.com/mersel-dss/mersel-dss-server-signer-java/issues/7)) |
| **Trusted root** | `TRUSTED_ROOT_CERT_FOLDER_PATH` | — | Custom kök sertifika klasörü |
| CORS | `CORS_ALLOWED_ORIGINS` | `*` | Production'da spesifik domain |
| JVM | `JAVA_OPTS` | (deployment-spesifik) | Heap, GC, security flag'leri |

> Her deployment klasörünün kendi `*.env.example` dosyasında bu listenin **deployment'a özgü yorumlu sürümü** bulunur.

---

## Sertifika (PFX) Yerleşim Konvansiyonu

Production deployment'larda PFX dosyası **uygulama jar'ı ile aynı yerde tutulmaz**. Tavsiye ettiğimiz dizinler:

| Platform | PFX Dizini | İzin |
|---|---|---|
| Linux / SystemD | `/etc/mersel-dss-signer/certs/` | `0750 root:signer`, dosya `0400` |
| Windows Service | `C:\ProgramData\mersel-dss-signer\certs\` | NTFS ACL: SYSTEM + Administrators only |
| Docker | Bind-mount: `-v /host/certs:/app/certs:ro` | Read-only |
| Kubernetes | `Secret` (base64) → `volumeMount` | RBAC ile sınırlı |

Bu konvansiyon **defense-in-depth** sağlar:
- `signer` kullanıcısı sadece kendi okuduğu dosyaları görür.
- Uygulama compromise olsa bile PFX'i farklı yere kopyalayamaz.
- Log dump'lara PFX yolu düşse bile başka süreç dosyaya erişemez.

Repo'daki **test sertifikaları** (`resources/test-certs/*.pfx`) public KamuSM test PFX'leridir; production deployment'a SİZMAZ — `Dockerfile`'ın `COPY` adımı `test-certs` opsiyonel pattern'iyle yapılır, production env'inde **kendi** PFX'inizi mount edersiniz.

---

## Smoke Test (Deployment Sonrası)

```bash
# Health
curl http://localhost:8085/actuator/health
# {"status":"UP"}

# Info
curl http://localhost:8085/actuator/info

# Metrikler (Prometheus formatı)
curl http://localhost:8085/actuator/prometheus | head -50

# Sertifika bilgisi (uygulama düzgün cert okudu mu?)
curl http://localhost:8085/info-certificate
```

Daha kapsamlı smoke test için: [`devops/monitoring/load-test.sh`](./monitoring/load-test.sh) — 6 farklı endpoint'i ardışık çağırır.

---

## İlgili Dokümanlar

- [`docs/RUN_PROFILES.md`](../docs/RUN_PROFILES.md) — Spring profile mimarisi (IDE + CLI)
- [`DSS_OVERRIDE.md`](../DSS_OVERRIDE.md) — DSS upstream override'ları (XAdES SigningTime vb.)
- [Ana dokümantasyon](https://dss.mersel.dev) — Merkezi developer portal
- [Actuator Endpoints](https://dss.mersel.dev/sign-api/actuator-endpoints) — Health/Info/Metrics referansı
