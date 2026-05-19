# Linux SystemD Servisi

> **TL;DR** — JAR'ı `mvn package` ile üret, `sudo ./install.sh` çalıştır, env dosyasını düzenle, `sudo systemctl start mersel-dss-signer`. Tamam.

Mersel DSS Signer API'yi Linux (Ubuntu / Debian / RHEL / Rocky / Alma) üzerinde **hardened**, otomatik-restart edebilen ve `journalctl` ile takip edilebilen bir SystemD servisi olarak çalıştırmak içindir.

---

## İçindekiler

- [1. Klasör İçeriği](#1-klasör-içeriği)
- [2. Hızlı Kurulum (otomatik)](#2-hızlı-kurulum-otomatik)
- [3. Manuel Kurulum](#3-manuel-kurulum)
- [4. Env Dosyası](#4-env-dosyası)
- [5. Operasyon Komutları](#5-operasyon-komutları)
- [6. PFX vs HSM Senaryoları](#6-pfx-vs-hsm-senaryoları)
- [7. Hardening Notları](#7-hardening-notları)
- [8. Reverse Proxy (nginx) Önerisi](#8-reverse-proxy-nginx-önerisi)
- [9. Sorun Giderme](#9-sorun-giderme)
- [10. Kaldırma](#10-kaldırma)

---

## 1. Klasör İçeriği

```
devops/systemd/
├── mersel-dss-signer.service        # SystemD unit dosyası (hardened)
├── mersel-dss-signer.env.example    # EnvironmentFile şablonu
├── install.sh                       # Otomatik kurulum (user + dizinler + unit)
├── uninstall.sh                     # Temiz kaldırma (--purge ile env+log+user dahil)
└── README.md                        # Bu dosya
```

---

## 2. Hızlı Kurulum (otomatik)

```bash
# 1) Repo kökünden JAR üret
mvn clean package -DskipTests

# 2) Kurulum script'ini çalıştır (signer user + dizinler + unit yerleştirir)
sudo ./devops/systemd/install.sh

# 3) Env dosyasını düzenle — CERTIFICATE_PIN, PFX_PATH / PKCS11_LIBRARY vs.
sudo nano /etc/mersel-dss-signer/mersel-dss-signer.env

# 4) Servisi başlat
sudo systemctl start mersel-dss-signer

# 5) Sağlık kontrolü
curl http://localhost:8085/actuator/health
sudo journalctl -u mersel-dss-signer -f
```

`install.sh` idempotent'tir: birden çok kez çalıştırılabilir, mevcut env dosyasının üzerine yazmaz.

---

## 3. Manuel Kurulum

Script'i kullanmak istemiyorsan adımlar:

```bash
# Kullanıcı
sudo useradd --system --no-create-home \
             --home-dir /opt/mersel-dss-signer \
             --shell /usr/sbin/nologin signer

# Dizinler
sudo install -d -o signer -g signer -m 0755 /opt/mersel-dss-signer/{logs,work}
sudo install -d -o signer -g signer -m 0755 /var/log/mersel-dss-signer
sudo install -d -o root   -g signer -m 0750 /etc/mersel-dss-signer/certs

# JAR
sudo install -o signer -g signer -m 0644 \
     target/mersel-dss-signer-api-*.jar \
     /opt/mersel-dss-signer/mersel-dss-signer-api.jar

# Unit
sudo install -o root -g root -m 0644 \
     devops/systemd/mersel-dss-signer.service \
     /etc/systemd/system/mersel-dss-signer.service

# Env
sudo install -o root -g signer -m 0640 \
     devops/systemd/mersel-dss-signer.env.example \
     /etc/mersel-dss-signer/mersel-dss-signer.env
sudo nano /etc/mersel-dss-signer/mersel-dss-signer.env  # düzenle

# Etkinleştir + başlat
sudo systemctl daemon-reload
sudo systemctl enable --now mersel-dss-signer
```

---

## 4. Env Dosyası

`/etc/mersel-dss-signer/mersel-dss-signer.env` dosyasında **secret** değerler tutulur. Dosya izni **0640**, sahibi **root:signer** olmalıdır — başka kullanıcılar PIN'i okuyamamalı.

```bash
sudo chmod 0640 /etc/mersel-dss-signer/mersel-dss-signer.env
sudo chown root:signer /etc/mersel-dss-signer/mersel-dss-signer.env
sudo ls -l /etc/mersel-dss-signer/mersel-dss-signer.env
# -rw-r----- 1 root signer ...
```

### Önemli Değişkenler

| Değişken | Senaryo | Açıklama |
|---|---|---|
| `CERTIFICATE_PIN` | her senaryo | PFX parolası veya HSM PIN'i |
| `PFX_PATH` | PFX | PFX dosyasının tam yolu (`/etc/mersel-dss-signer/certs/...`) |
| `CERTIFICATE_ALIAS` | her senaryo | Alias (default: `1`) |
| `PKCS11_LIBRARY` | HSM | AKİS sürücüsü yolu (`.so`) |
| `PKCS11_SLOT` / `PKCS11_SLOT_LIST_INDEX` | HSM | Slot seçimi (-1 = auto) |
| `IS_TUBITAK_TSP` | TSP | TÜBİTAK TSP modu (otomatik tespit, açıkça override edilebilir) |
| `TS_SERVER_HOST` | TSP | TSP endpoint URL |
| `TS_USER_ID` / `TS_USER_PASSWORD` | TSP | TÜBİTAK abone kimlik bilgileri |
| `XADES_SIGNING_TIME_ZONE` | XAdES | SigningTime timezone (default `+03:00`, [issue #7](https://github.com/mersel-dss/mersel-dss-server-signer-java/issues/7)) |
| `SERVER_PORT` | runtime | HTTP port (default 8085) |
| `LOG_LEVEL` | runtime | `INFO` / `DEBUG` / `WARN` |
| `SPRING_PROFILES_ACTIVE` | runtime | Genelde **boş bırakın**; test profili için `local,pfx-kurum01-rsa2048` vb. (bkz. [docs/RUN_PROFILES.md](../../docs/RUN_PROFILES.md)) |

Tam şablon: [`mersel-dss-signer.env.example`](./mersel-dss-signer.env.example)

---

## 5. Operasyon Komutları

```bash
# Durum
sudo systemctl status mersel-dss-signer

# Logları izle (real-time)
sudo journalctl -u mersel-dss-signer -f

# Son 200 satır
sudo journalctl -u mersel-dss-signer -n 200 --no-pager

# Hata seviyesinde filtrele
sudo journalctl -u mersel-dss-signer -p err --since "1 hour ago"

# Restart
sudo systemctl restart mersel-dss-signer

# Durdur / Başlat
sudo systemctl stop mersel-dss-signer
sudo systemctl start mersel-dss-signer

# Boot'ta otomatik başlama on/off
sudo systemctl enable mersel-dss-signer
sudo systemctl disable mersel-dss-signer

# Env değişikliğini uygula (Spring property dosyası bunu okur):
sudo systemctl restart mersel-dss-signer

# Unit dosyası değişikliği sonrası:
sudo systemctl daemon-reload && sudo systemctl restart mersel-dss-signer
```

---

## 6. PFX vs HSM Senaryoları

### PFX (Yumuşak Keystore)

Production PFX'i dağıtım sunucusuna manuel kopyala:

```bash
# Operatör laptop'undan
scp production.pfx admin@signer-prod:/tmp/

# Sunucuda
sudo install -o signer -g signer -m 0400 \
     /tmp/production.pfx \
     /etc/mersel-dss-signer/certs/production.pfx
sudo rm /tmp/production.pfx
```

Env dosyasında:

```ini
PFX_PATH=/etc/mersel-dss-signer/certs/production.pfx
CERTIFICATE_PIN=__GERCEK_PAROLA__
CERTIFICATE_ALIAS=1
```

### HSM (AKİS / PKCS#11)

PC/SC + AKİS sürücüsü kurulumu (Ubuntu örneği):

```bash
# PC/SC daemon
sudo apt-get install -y pcscd pcsc-tools libccid

# AKİS sürücüsü — KamuSM resmi tar.gz veya distro paketi
# Manuel kurulum sonrası:
ls -la /usr/local/lib/libakisp11.so

# Servisleri başlat
sudo systemctl enable --now pcscd

# Kart algılama testi
pcsc_scan
# "AKIA Smartcard" veya benzeri tag görüyor olmalısın
```

Env dosyasında:

```ini
PKCS11_LIBRARY=/usr/local/lib/libakisp11.so
PKCS11_SLOT=-1
PKCS11_SLOT_LIST_INDEX=-1
PKCS11_NULL_INIT_ARGS=false
CERTIFICATE_PIN=__KART_PIN__
```

> **`pcscd` bağımlılığı**: Unit dosyasında `Wants=pcscd.service` var. PFX-only deployment'larda zararsız — pcscd yoksa yine kalkar.

---

## 7. Hardening Notları

Unit dosyası şu kısıtları aktif eder:

| Direktif | Etki |
|---|---|
| `NoNewPrivileges=true` | setuid/setgid binary'ler yetki yükseltemez |
| `ProtectSystem=strict` | `/usr`, `/boot`, `/etc` salt-okunur |
| `ProtectHome=true` | `/home`, `/root`, `/run/user` görünmez |
| `PrivateTmp=true` | İzole `/tmp` (host /tmp'i etkilemez) |
| `ProtectKernelTunables/Modules=true` | sysctl/modprobe yasak |
| `RestrictNamespaces/Realtime/SUIDSGID=true` | Sandbox sıkılaştırma |
| `LockPersonality=true` | personality() syscall yasak |
| `LimitNOFILE=65536` | TLS handshake bol soket için |

### `MemoryDenyWriteExecute=false` Neden?

JVM'in JIT'i code cache'i `RWX` mapping ile tutar (G1 GC, C1/C2). `MDWX=true` verirsen JVM `SIGSEGV` ile crash eder. Bunu **açık bırakmak güvenlik kaybı değil** — JIT compilation'ın doğal davranışıdır.

### `PrivateDevices=no` Neden?

`true` verirsen `/dev/bus/usb` görünmez, **AKİS smart card okuyucu çalışmaz**. PFX-only deployment'ta `true`'ya çevirebilirsin (ek hardening).

### Ek Kısıt (opsiyonel)

Sadece localhost'tan bağlanılacaksa (örn. nginx önde):

```ini
[Service]
IPAddressAllow=127.0.0.1 ::1
IPAddressDeny=any
```

---

## 8. Reverse Proxy (nginx) Önerisi

Spring Boot built-in Tomcat'i public expose etmek yerine nginx arkasına alın:

```nginx
upstream signer_api {
    server 127.0.0.1:8085 max_fails=3 fail_timeout=30s;
    keepalive 16;
}

server {
    listen 443 ssl http2;
    server_name sign-api.example.gov.tr;

    ssl_certificate     /etc/letsencrypt/live/sign-api.example.gov.tr/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sign-api.example.gov.tr/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    # PDF / XML upload'ları için (application.properties default'u 200MB)
    client_max_body_size 200M;
    client_body_timeout  120s;
    proxy_read_timeout   300s;

    # Health endpoint dışarıya açılmasın
    location /actuator/ {
        allow 10.0.0.0/8;
        allow 127.0.0.1;
        deny  all;
        proxy_pass http://signer_api;
    }

    location / {
        proxy_pass         http://signer_api;
        proxy_http_version 1.1;
        proxy_set_header   Connection        "";
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

---

## 9. Sorun Giderme

### Servis kalkmıyor — "Permission denied"

```bash
sudo journalctl -u mersel-dss-signer -n 50
# Genelde PFX_PATH veya PKCS11_LIBRARY izinleri sorun
sudo ls -la /etc/mersel-dss-signer/certs/
sudo -u signer cat /etc/mersel-dss-signer/certs/production.pfx >/dev/null && echo OK
```

`signer` kullanıcısı PFX'i okuyamıyorsa: `chown signer:signer` ve `chmod 0400`.

### "PKCS11 library not found"

```bash
# Sürücü kurulu mu?
ls -la /usr/local/lib/libakisp11.so /usr/lib/x86_64-linux-gnu/libakisp11.so 2>/dev/null

# pcscd çalışıyor mu?
systemctl status pcscd

# Kart görünüyor mu?
sudo -u signer pcsc_scan -n
```

### "Address already in use" — port 8085

```bash
sudo ss -tlnp | grep 8085
# Başka süreç tutuyor — durdur veya SERVER_PORT'u env dosyasında değiştir
```

### Env değişikliği uygulanmıyor

`systemctl restart` SHART, sadece `reload` yetmez:

```bash
sudo systemctl restart mersel-dss-signer
```

### Spring Boot başlangıçta crash — "OOM" 

Default heap 1g. Yüksek concurrency için env dosyasında:

```ini
JAVA_OPTS=-Xms512m -Xmx2g -XX:+UseG1GC -XX:MaxGCPauseMillis=100 -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/var/log/mersel-dss-signer
```

### `journalctl` boş çıkıyor

Log unit identifier'ı SHART eşleşmeli:

```bash
sudo journalctl -t mersel-dss-signer -n 100  # SyslogIdentifier ile
```

---

## 10. Kaldırma

```bash
# Servisi kaldır — env ve loglar KORUNUR
sudo ./devops/systemd/uninstall.sh

# Komple temizlik — env + log + user dahil
sudo ./devops/systemd/uninstall.sh --purge
```

---

## İlgili Dokümanlar

- [docs/RUN_PROFILES.md](../../docs/RUN_PROFILES.md) — Spring profile mimarisi
- [devops/docker/](../docker/) — Docker deployment (alternatif)
- [devops/monitoring/](../monitoring/) — Prometheus + Grafana entegrasyonu
- [Ana dokümantasyon](https://dss.mersel.dev)
