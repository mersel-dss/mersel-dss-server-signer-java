# Signer Notifications — Operatör Rehberi

Bu doküman, **Mersel DSS Signer API**'nin **iki sınıf olayda** kuracağı
bildirim mekanizmasını anlatır:

1. **`signature-failure`** — Herhangi bir imza endpoint'inde
   (XAdES, CAdES, PAdES, WS-Security, Hash, Timestamp) yakalanan bir
   exception. Request thread'inde tetiklendiği için `x-log-*`
   korelasyon header'ları payload'a + Slack mesajına otomatik dahil
   edilir.
2. **`heartbeat-*`** (5 alt-tip) — HSM heartbeat scheduler'ın state
   transition'ları (kanal teardown, self-healing, recovery). Heartbeat
   scheduler thread'inde çalıştığı için request bağlamı yoktur;
   `x-log-*` alanı boş gider.

Aynı sistem 4 dış-iletişim kanalını destekler:

- **Generic webhook** — operatörün kendi alert/ticket/SIEM sistemine
  JSON POST (event metadata + opsiyonel base64 içerik + HMAC imza)
- **Slack incoming webhook** — Slack kanalında renk-kodlu Block Kit
  alarm mesajı (kırmızı = failure, turuncu = heartbeat alarm,
  yeşil = heartbeat recovery)
- **Slack-only inline base64** — bot token / external storage
  kuramayacağı senaryolar için: imzalanmaya çalışılan dosya base64 +
  code block olarak doğrudan Slack mesajının **içine** gömülür
  (tek-URL kurulum, yalnız signature-failure)
- **Slack bot file upload** — aynı anda imzalanmaya çalışılan dosyayı
  kanala indirilebilir ek olarak yükleme (yeni 3-adımlı Slack API;
  heartbeat olaylarında devreye girmez — dosya yok)

Tüm bu kanallar **birbirinden bağımsız**dır; sadece ilgili env
değişkenleri set edilerek aktivasyon yapılır. İmza akışı ve heartbeat
scheduler tick'i asla bildirim hatasından etkilenmez (best-effort,
async).

---

## 1. Hızlı başlangıç

```bash
# A) Sadece generic webhook'una alert at:
export SIGNER_WEBHOOK_URL=https://alerts.example.com/hooks/mersel-dss-signer
export SIGNER_WEBHOOK_SECRET=$(openssl rand -hex 32)   # önerilir

# B) Sadece Slack'e renk-kodlu alert mesajı:
export SIGNER_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T0/B0/XXX

# C) ÖNERİLEN (PRODUCTION) — Slack mesajına ek olarak imzalanmaya çalışılan
#    dosyayı indirilebilir ek olarak yükle. Slack ekosisteminin İÇİNDE
#    kalır (files.slack.com), 1GB'a kadar. PDF/UBL faturalar (>50KB) için
#    TEK doğru yol; inline base64'e sığmaz.
export SIGNER_SLACK_BOT_TOKEN=xoxb-…
export SIGNER_SLACK_CHANNEL=C0123456789                # kanal ADI değil, ID

# D) Bot token kuramıyorsan VE dosyalar ≤28KB ise: dosyayı Slack mesajının
#    İÇİNE göm. Yalnız incoming webhook URL yetiyor — bot yok, harici depo yok.
#    Default 8KB cap; küçük XAdES tek-imza dosyaları için ideal.
#    DİKKAT: >28KB için Slack mesaj 40k char limitini aşar → C seçeneğine geç.
#    NOT: Inline base64 yalnız signature-failure için anlamlı (heartbeat'te dosya yok).
export SIGNER_SLACK_INLINE_BASE64_ENABLED=true
export SIGNER_SLACK_INLINE_BASE64_MAX_BYTES=8192       # default; max ~28000 güvenli

# Gizlilik kısıtı varsa base64 içeriği webhook payload'una da gönderme:
# (Mali Mühür PDF içinde VKN/TCKN gibi PII olabilir)
export SIGNER_NOTIFICATION_INCLUDE_CONTENT=false

# Event-seviye susturma — sadece heartbeat istiyorsan signature-failure'ı kapat:
export SIGNER_NOTIFICATION_SIGNATURE_FAILURE_ENABLED=false

# Geçici topyekun susturma (URL'leri sökmeden):
export SIGNER_NOTIFICATION_ENABLED=false
```

---

## 2. Hangi event ne zaman tetiklenir?

### 2.1 `signature-failure`

Aşağıdaki **6 imza endpoint'inin** herhangi birinde bir exception
yakalanırsa tetiklenir:

| Endpoint | İmza Tipi | Tipik Hata Sebebi |
|---|---|---|
| `POST /v1/xadessign` | XAdES | XML namespace / canonicalization / TSA timeout |
| `POST /v1/wssecuritysign` | WS-Security | SOAP envelope parse / WSS token oluşturma |
| `POST /v1/cadessign` | CAdES | CMS encoding / sertifika zinciri eksik |
| `POST /v1/padessign` | PAdES | PDF append-mode incrementality / signature placeholder |
| `POST /v1/hashsign` | Hash | Digest uzunluğu/algoritma mismatch / HSM C_Sign fail |
| `POST /api/timestamp/get` | Timestamp | TSA bağlantı / kontör tükenmiş / hash algoritma desteklenmiyor |

> **Bildirim atılmayan durumlar** (operasyonel gürültü kontrolü):
> - `HashSignatureController` içinde `IllegalArgumentException` (4xx
>   kullanıcı hata — bildirim üretmez)
> - `/api/timestamp/validate` ve `/api/timestamp/status` (sadece
>   okuma operasyonu — alarm konusu değil)

### 2.2 `heartbeat-*` (5 alt-tip)

`HSM_HEARTBEAT_ENABLED=true` ve `PKCS11_LIBRARY` set'liyken çalışan
`HsmHeartbeatScheduler` aşağıdaki state transition'larda bildirim üretir:

| Event Code | Ne zaman? | Slack rengi | Tetik gürültü kontrolü |
|---|---|---|---|
| `heartbeat-failed` | Heartbeat `C_Sign` round-trip hata attı | turuncu | İlk failure'da (`consecutive==1`) **ve** eşik aşımının ilk anında (`consecutive==5`) bildirilir — aradaki her başarısız tick'te değil |
| `heartbeat-recovered` | Önce ardışık başarısızlık vardı, şimdi sign başarılı | yeşil | Sadece transition'da (alarm temizliği) |
| `heartbeat-reinit-triggered` | Ardışık başarısızlık 3'ü aştı, Cryptoki `C_Finalize + C_Initialize` deneniyor | turuncu | Her reinit denemesinde |
| `heartbeat-reinit-success` | Reinit başarılı, private key handle yenilendi | yeşil | Her başarılı reinit'te |
| `heartbeat-reinit-failed` | Reinit başarısız — backoff penceresine girildi | turuncu | Her başarısız reinit'te (operatör müdahale gerekebilir) |

State machine:

```
(success) --(C_Sign fails)--> FAILED [bildirim @ consecutive=1, =5]
FAILED --(consec ≥ 3)----> REINIT_TRIGGERED [bildirim]
REINIT_TRIGGERED --(success)--> REINIT_SUCCESS [bildirim]
REINIT_TRIGGERED --(fail)----->  REINIT_FAILED [bildirim]
FAILED|REINIT_* --(C_Sign ok)--> RECOVERED [bildirim]
```

> **Gürültü kontrolü kuralları** üretimden öğrenilmiş: 22 Mayıs 2026
> incident'inde 3297× ardışık başarısız heartbeat oldu. Her tick'te
> bildirim atsaydık operatörü boğardık. Sadece *ilk failure* ve
> *ERROR threshold* anlarında alarm üretiyoruz; ortadaki sessiz log
> kayıtları zaten Logback'te.

---

## 3. Hangi modu seçeyim? — Boyut bazlı karar rehberi

`signature-failure` event'leri için imzalanmaya çalışılan dosyanın
boyutuna göre **en doğru** dağıtım modu (heartbeat olaylarında dosya
yoktur, boyut tartışması yoktur):

| Tipik dosya boyutu | Önerilen mod | Neden |
|---|---|---|
| **≤8KB** (küçük XAdES, hash digest, SOAP zarfı parçası) | Slack-only inline base64 | Tek-URL kurulum; chat'te direkt görünür |
| **8KB – 28KB** (orta XAdES, çok-imzalı XML) | Slack-only inline base64 + `MAX_BYTES` arttır | Hâlâ tek-URL; Slack 40k char mesaj limitiyle ⚠️ dikkatli (binary ≤28KB güvenli üst sınır) |
| **>28KB** (PDF imzalı fatura, 250KB UBL paketi…) | **Slack bot file upload** | Inline'a fiziksel SIĞMIYOR; bot upload Slack ekosisteminin İÇİNDE kalır (`files.slack.com`), 1GB'a kadar |
| Çok büyük (>10MB) veya gizlilik kritik | Generic webhook + receiver tarafında base64 dump | Slack zaten 1GB üstünü almaz; receiver tarafında kontrollü arşivleme |

**Matematik özet** — neden 250KB inline'a sığmaz:

```
binary boyutu × 4/3 (base64 expansion) ≈ Slack mesajındaki char
+ Block Kit overhead + decode hint + chunk fences
─────────────────────────────────────────────
ÜST SINIR: Slack mesajı toplam 40,000 char (sert sınır)

250KB × 4/3 = ~333,000 char    →   8× kat fazla, REDDEDİLİR (400 invalid_blocks)
 28KB × 4/3 =  ~37,300 char    →   güvenli üst sınır
  8KB × 4/3 =  ~10,900 char    →   default; ~5 chunk, rahatça sığar
```

---

## 4. Aktivasyon matrisi

| Env Var Set | Etki |
|---|---|
| `SIGNER_WEBHOOK_URL` | Generic webhook aktif (her iki event tipi için) |
| `SIGNER_WEBHOOK_URL` + `SIGNER_WEBHOOK_SECRET` | Generic webhook + HMAC imza |
| `SIGNER_SLACK_WEBHOOK_URL` | Slack kanal mesajı (renk-kodlu Block Kit) |
| `SIGNER_SLACK_WEBHOOK_URL` + `SIGNER_SLACK_INLINE_BASE64_ENABLED=true` | Slack mesajı + dosya inline base64 (tek-URL mod; yalnız signature-failure'da etkin) |
| `SIGNER_SLACK_BOT_TOKEN` + `SIGNER_SLACK_CHANNEL` | Slack'e indirilebilir dosya upload (her boyut; yalnız signature-failure'da etkin — heartbeat'te dosya yok) |
| Hiçbiri | No-op (sıfır network/heap maliyeti — OkHttpClient bile kurulmaz) |
| `SIGNER_NOTIFICATION_ENABLED=false` | Hepsi susturulur (URL'ler kalsa bile) |
| `SIGNER_NOTIFICATION_SIGNATURE_FAILURE_ENABLED=false` | Yalnız signature-failure susturulur; heartbeat aktif kalır |
| `SIGNER_NOTIFICATION_HEARTBEAT_ENABLED=false` | Yalnız heartbeat susturulur; signature-failure aktif kalır |

> **Önemli**: Slack bot file upload için **hem token hem kanal ID**
> gerekli. Token tek başına aktivasyon için yetmez (Slack
> `completeUploadExternal` API'si çağrıyı channel ile bağlar).

---

## 5. Generic webhook payload şeması

### 5.1 Signature-failure event payload'ı

```json
{
  "event": "signature-failure",
  "source": "mersel-dss-signer-api/0.9.2",
  "notificationTime": "2026-05-26T11:13:20.000+00:00",
  "file": {
    "name": "fatura-2026-00042.xml",
    "sizeBytes": 18234,
    "contentType": "application/xml",
    "sha256Hex": "a3f8c9b1...",
    "base64Content": "PD94bWwgdmVyc2lvbj0iMS4wIiB...",
    "contentOmittedReason": null
  },
  "signatureFailure": {
    "endpoint": "/v1/xadessign",
    "signatureType": "XAdES",
    "errorClass": "io.mersel.dss.signer.api.exceptions.SignatureException",
    "errorCode": "KEYSTORE_INIT_FAIL",
    "errorMessage": "PKCS#11 token login failed: CKR_PIN_INCORRECT"
  },
  "logHeaders": {
    "x-log-id": "req-7f8a9b",
    "x-log-tenant": "finsel",
    "x-log-trace-id": "abc123..."
  }
}
```

**Önemli alanlar**:

- `file.base64Content` — `SIGNER_NOTIFICATION_INCLUDE_CONTENT=false`
  veya dosya `SIGNER_NOTIFICATION_MAX_CONTENT_SIZE_BYTES` (default
  10MB) üstündeyse **null** gelir; bu durumda `contentOmittedReason`
  doludur (`EXCLUDED_BY_CONFIG` veya `EXCEEDED_MAX_SIZE`).
- `file.sha256Hex` — her zaman doludur (içerik atlansa bile).
  Receiver dosyayı kendi arşivinden eşleştirebilsin diye.
- `signatureFailure.errorCode` — yalnız
  `io.mersel.dss.signer.api.exceptions.SignatureException` ve
  türevlerinde doludur (`getErrorCode()` dönüşü). Generic Exception'da
  null.
- `logHeaders` — request'e `x-log-*` prefix'iyle gelen tüm header'lar.
  Hiç yoksa veya bağlam request thread'i değilse null.

### 5.2 Heartbeat event payload'ı

```json
{
  "event": "heartbeat-failed",
  "source": "mersel-dss-signer-api/0.9.2",
  "notificationTime": "2026-05-26T11:13:20.000+00:00",
  "heartbeat": {
    "eventType": "FAILED",
    "alias": "akis-rsa-2048",
    "signatureAlgorithm": "RSA_SHA256",
    "successCount": 1247,
    "failureCount": 1,
    "consecutiveFailures": 1,
    "reinitAttempts": 0,
    "reinitSuccesses": 0,
    "errorClass": "iaik.pkcs.pkcs11.wrapper.PKCS11Exception",
    "errorMessage": "CKR_SMS_ERROR (0x80000384)"
  }
}
```

**Heartbeat event'leri için NULL alanlar**:

- `file` — heartbeat'in dosyası yoktur, ALWAYS null
- `signatureFailure` — başka event tipi, ALWAYS null
- `logHeaders` — heartbeat scheduler thread'inde request bağlamı yok,
  genelde null

`heartbeat.errorClass` ve `heartbeat.errorMessage` sadece `FAILED` ve
`REINIT_FAILED` event'lerinde doludur; `RECOVERED`/`REINIT_SUCCESS`/
`REINIT_TRIGGERED`'da null.

### 5.3 Şema kararlılığı

Alan adları **kararlı API kontratıdır**; silinmez, yeniden adlandırılmaz.
Yeni alanlar eklenebilir (forward-compatible). `event` alanı discriminator
olarak ilk önce parse edilmeli; receiver bu değere göre `file`,
`signatureFailure` veya `heartbeat` sub-object'lerinden hangisinin
dolu olacağını bilir.

---

## 6. Webhook HTTP header'ları & HMAC doğrulama

| Header | Her zaman | Açıklama |
|---|---|---|
| `X-Mersel-Event: <eventCode>` | ✅ | `signature-failure` veya `heartbeat-*` |
| `X-Mersel-Webhook-Id: <uuid>` | ✅ | Her bildirim için eşsiz — idempotency |
| `X-Mersel-Webhook-Timestamp: <epoch-seconds>` | ✅ | Replay protection |
| `X-Mersel-Signature: sha256=<hex>` | Secret set ise | HMAC-SHA256(`"{ts}.{rawBody}"`, secret) |
| `User-Agent: mersel-dss-signer-api/<ver>` | ✅ | Versiyon |
| `x-log-*: <value>` | İlgili event'te varsa | Request thread'inde gelen korelasyon header'ları (pass-through) |

### Receiver tarafında doğrulama (Node.js örneği)

```javascript
const crypto = require('crypto');

function verifyMerselWebhook(req, secret) {
  const sigHeader = req.headers['x-mersel-signature'];
  const ts = req.headers['x-mersel-webhook-timestamp'];
  const rawBody = req.rawBody;  // Express: body-parser raw veya bytes

  // 1) Replay protection: timestamp 5 dakikadan eski olmasın
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - parseInt(ts, 10)) > 300) {
    throw new Error('webhook timestamp out of window');
  }

  // 2) HMAC kontrolü — constant-time karşılaştırma şart
  const expected = 'sha256=' + crypto
    .createHmac('sha256', secret)
    .update(`${ts}.${rawBody}`)
    .digest('hex');

  if (!crypto.timingSafeEqual(
        Buffer.from(sigHeader), Buffer.from(expected))) {
    throw new Error('webhook signature mismatch');
  }
}
```

### Python örneği

```python
import hmac, hashlib, time

def verify(headers, raw_body: bytes, secret: str) -> None:
    ts = int(headers['X-Mersel-Webhook-Timestamp'])
    if abs(time.time() - ts) > 300:
        raise ValueError('timestamp out of window')

    expected = 'sha256=' + hmac.new(
        secret.encode('utf-8'),
        f'{ts}.'.encode('utf-8') + raw_body,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(headers['X-Mersel-Signature'], expected):
        raise ValueError('signature mismatch')

    # Event tipine göre dispatch:
    event = headers.get('X-Mersel-Event', '')
    if event == 'signature-failure':
        handle_signature_failure(raw_body)
    elif event.startswith('heartbeat-'):
        handle_heartbeat(event, raw_body)
```

### Java örneği

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

static boolean verify(
        String tsHeader, String sigHeader, byte[] rawBody, String secret) {
    long ts = Long.parseLong(tsHeader);
    if (Math.abs(System.currentTimeMillis() / 1000 - ts) > 300) {
        return false;
    }
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
    String message = ts + ".";
    mac.update(message.getBytes(StandardCharsets.UTF_8));
    byte[] computed = mac.doFinal(rawBody);
    StringBuilder hex = new StringBuilder(computed.length * 2);
    for (byte b : computed) hex.append(String.format("%02x", b & 0xff));
    String expected = "sha256=" + hex;
    return MessageDigest.isEqual(
        expected.getBytes(StandardCharsets.UTF_8),
        sigHeader.getBytes(StandardCharsets.UTF_8));
}
```

> **Constant-time karşılaştırma** zorunlu — `==` veya `equals()` ile
> karşılaştırırsanız timing saldırılarına açık kalırsınız.

---

## 7. Slack incoming webhook mesajı

Mesaj `attachments` legacy field'ı içinde Block Kit ile gönderilir;
bu sayede mesajın sol tarafında **renk-kodlu dikey şerit** görünür:

| Event tipi | Renk | Hex | Anlam |
|---|---|---|---|
| `signature-failure` | Kırmızı | `#A30200` | Müşteri imza isteği başarısız |
| `heartbeat-failed`, `heartbeat-reinit-triggered`, `heartbeat-reinit-failed` | Turuncu | `#D97706` | HSM sorunu — operasyonel alarm |
| `heartbeat-recovered`, `heartbeat-reinit-success` | Yeşil | `#2EB67D` | Pozitif sinyal — alarm temizliği |

### 7.1 Signature-failure mesajı içeriği

1. **Header** — "🚨 Mersel DSS Signer - SIGNATURE FAILURE"
2. **Summary fields** — Endpoint, İmza Tipi, Dosya, Boyut, Hata Sınıfı,
   (varsa) Hata Kodu
3. **Korelasyon (x-log-*)** — request thread'inde toplanan header'lar
   (en fazla 10 satır, kalan webhook payload'unda)
4. **Hata mesajı** — exception `getMessage()` (truncated, ≤1500 char)
5. **(Opsiyonel) Inline base64** — `SLACK_INLINE_BASE64_ENABLED=true`
   ise dosya code-fenced chunk'larında

### 7.2 Heartbeat mesajı içeriği

1. **Header** — "⚠️ Mersel DSS Signer - HSM heartbeat sign FAILED"
   (veya `✅` + event'in human label'ı)
2. **Summary fields** — Event code, Alias, Algoritma, Toplam Başarı,
   Toplam Başarısızlık, Ardışık Başarısızlık, Reinit Denemesi,
   Reinit Başarısı
3. **(Varsa) Hata mesajı** — sadece FAILED / REINIT_FAILED'da

Heartbeat mesajına dosya/base64 dahil edilmez (heartbeat'in dosyası
yoktur — kontrat gereği).

---

## 8. Slack-only / Single-URL deployment — Inline Base64 (≤28KB)

> **Yalnız `signature-failure` event'inde anlamlı** — heartbeat
> olaylarında dosya yoktur. `SLACK_INLINE_BASE64_ENABLED=true` yapsanız
> da heartbeat mesajları metadata-only basit kalır.

**Ne zaman lazım?** Bot token + `files:write` scope yönetmek
istemediğiniz / kuramayacağınız durumlar:

- Kurumsal IT politikası bot creation'a izin vermiyor.
- Hızlı POC veya küçük ekip — kurulum yükünü minimize etmek istiyorsunuz.
- Externalde dosya barındıracak yer yok / istemiyorsunuz; her şey
  Slack içinde kalsın.

Bu modda yalnızca **bir tek Slack incoming webhook URL'i** set
edersiniz; imzalanmaya çalışılan dosya base64 olarak Slack mesajının
**içine** — triple-backtick code block içinde — gömülür. Operatör için
decode bir `pbpaste | base64 -d` komutu.

### 8.1 Aktivasyon

```bash
export SIGNER_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T0/B0/XXX
export SIGNER_SLACK_INLINE_BASE64_ENABLED=true
# Opsiyonel — limit ayarı (default 8192 byte = 8KB)
export SIGNER_SLACK_INLINE_BASE64_MAX_BYTES=8192
```

> **Opt-in tasarımı**: Default `false`. Operatör bilinçli olarak
> `true` yapmadıkça Slack mesajı sade alarm olarak kalır (chat'i
> base64 dump'larıyla kirletmeme kuralı).

### 8.2 Boyut sınırı & chunking matematik

| Constraint | Değer | Notlar |
|---|---|---|
| Default `MAX_BYTES` | **8192** (8KB binary) | Base64 expansion 4/3× → ~10.9KB string |
| Slack mesaj toplam limit | 40,000 char | Default 8KB için rahatça altında |
| Block Kit per-section text | **3000 char (TIGHTER)** | Asıl darboğaz; 40k limitten önce vurur |
| Notifier chunk boyu | **2700 char** | 3000 - prefix/code-fence/decode-hint payı |
| Block Kit max blok/mesaj | 50 | 8KB için ~5 chunk yeterli, sınırın çok altında |

Notifier base64 string'ini otomatik olarak ~2700 char'lık parçalara
böler ve birden fazla section block'a basar. Round-trip garantisi:
chunk'lar sırayla concat edildiğinde orijinal base64'e **birebir**
eşit (tek char drift bile dosyayı bozar — `SignerNotifierTest`'te
korunur).

### 8.3 Limit aşılırsa ne olur?

Dosya `MAX_BYTES` üstündeyse inline base64 atlanır; mesaj yine gider
ama dosya yerine **omission notice satırı** belirir:

```
*İçerik:* Dosya boyutu (24576 bytes) Slack mesajı inline limiti (8192 bytes) aşıyor.
Operatör için en doğru yol Slack bot file upload (SIGNER_SLACK_BOT_TOKEN +
SIGNER_SLACK_CHANNEL set edin → dosya files.slack.com'a yüklenir).
Tam base64 içerik webhook payload'unda da mevcut.
```

Sessiz drop YOK — operatör Slack'te dosyanın neden eksik olduğunu
direkt görür.

### 8.4 Alıcı tarafı decode

**Tek-chunk durumu** (küçük dosyalar — ≤2KB binary):

```bash
# Slack'te code block içeriğini seç & kopyala, sonra:
pbpaste | base64 -d > document.bin      # macOS
xclip -o | base64 -d > document.bin     # Linux
```

**Multi-chunk durumu** (>2KB binary, birden fazla section block):

Tüm code block içeriklerini sırayla kopyalayın ve tek bir komuta
verin:

```bash
# Slack'teki tüm code block'ların içeriği birleştirilmiş halde clipboard'da:
pbpaste | base64 -d > document.bin
```

Slack mobil/desktop her ikisinde de code block içeriği seçilebilir
(triple-backtick monospace render sayesinde).

### 8.5 Bot upload ile karşılaştırma

| Boyut | Inline Base64 (single-URL) | Bot Upload (3-adımlı API) |
|---|---|---|
| **Kurulum** | 1 env var (`INLINE_BASE64_ENABLED=true`) | 4 adım (app oluştur + scope + install + invite) |
| **Bağımlılık** | Yalnız Slack incoming webhook URL | Bot token + kanal ID |
| **Dosya boyutu** | Default ≤8KB (config ile artırılabilir) | Slack default ≤1GB |
| **UX (download)** | Code block seç → terminal'de decode | Tek-tık download |
| **Mobile UX** | Code block selection (kısmen) | Native download |
| **Chat kirliliği** | Code block'lar mesajı uzatır | Mesaj sade, dosya ayrı görünür |
| **Heartbeat event'leri** | Etkisiz (dosya yok) | Etkisiz (dosya yok) |

İkisi aynı anda da set edilebilir (bağımsız kanallar); inline base64
operatörün "tek-URL deploy" trade-off'udur.

---

## 9. Slack bot file upload — production önerilen yol (3-adımlı yeni API)

> Bot upload yalnız `signature-failure` event'leri için anlamlıdır.
> Heartbeat event'lerinde devreye girmez (dosya yok).

Slack `files.upload` Kasım 2025'te sunset edildi. Modül artık zorunlu
olan 3-adımlı flow'u kullanır:

1. **`POST https://slack.com/api/files.getUploadURLExternal`**
   - Auth: `Bearer xoxb-…`
   - Form params: `filename`, `length`
   - → `{ ok: true, upload_url, file_id }`
2. **`POST <upload_url>`** — raw octet-stream byte'lar
   - Bu istekte token YOK; URL kendi içinde time-bound auth taşır
3. **`POST https://slack.com/api/files.completeUploadExternal`**
   - Auth: `Bearer xoxb-…`
   - JSON: `{ files: [{ id, title }], channel_id, initial_comment }`

### 9.1 Bot kurulumu — Adım adım (toplam ~4 dakika)

> **Slack workspace'inde admin haklarına ihtiyacın yok**; standart üye
> olarak da Slack app oluşturabilirsin. Workspace admini "Apps must be
> approved" politikası uygulamışsa app **pending** olur, admin
> onaylayınca token gelir. Bu yaygın değil — Slack workspace'inin
> çoğunda direkt çalışır.

#### YÖNTEM A — App Manifest ile hızlı kurulum (önerilen, ~2 dakika)

App Manifest YAML'i Slack'in resmi "bir bot'u tek dosyayla oluştur"
mekanizmasıdır. Aşağıdaki YAML'i kopyala-yapıştır yeterli:

1. **Aç**: <https://api.slack.com/apps?new_app=1>
2. **From an app manifest** seçeneğine tıkla
3. **Pick a workspace** → kendi workspace'ini seç → **Next**
4. **YAML** sekmesini seç (JSON değil), aşağıdaki manifest'i yapıştır:

```yaml
display_information:
  name: Mersel DSS Signer Notify
  description: SIGNATURE FAILURE ve HSM heartbeat alarmlarini Slack kanalina basar
  background_color: "#A30200"
features:
  bot_user:
    display_name: mersel-dss-signer-notify
    always_online: true
oauth_config:
  scopes:
    bot:
      - files:write       # signature-failure dosya upload icin yeterli (en az ayricalik)
      - chat:write        # initial_comment ve fallback chat icin
      # NOT: chat:write zaten incoming webhook tarafindan kullaniliyor;
      # bot upload icin yalniz files:write yeterli ama chat:write
      # bot'un kanala once mesaj atip sonra dosya upload etmesini
      # mumkun kilar (Slack tarafindaki bazi edge case'lerde gerekli).
settings:
  org_deploy_enabled: false
  socket_mode_enabled: false
  token_rotation_enabled: false
```

5. **Next** → **Create** butonuna tıkla
6. Sol menü → **Install App** → **Install to <WorkspaceAdı>**
   - Slack onay ekranı çıkar (bot ne yapacak özetle gösterir)
   - **Allow** butonuna tıkla
7. **Bot User OAuth Token** alanından `xoxb-...` token'ı **Copy**
   butonuyla kopyala — bu senin `SIGNER_SLACK_BOT_TOKEN` değerin.

> Token formatı: `xoxb-` ile başlar, ~70 char uzunluğunda. Eğer
> `xapp-` ile başlıyorsa **app-level token** kopyalamışsındır; o
> değil, **bot user OAuth token**'ı seç.

---

#### YÖNTEM B — Manuel UI tıklama (eğer manifest çalışmazsa, ~5 dakika)

1. **Aç**: <https://api.slack.com/apps>
2. **Create New App** → **From scratch**
3. **App Name**: `Mersel DSS Signer Notify` (istediğin isim olabilir)
   **Pick a workspace**: kendi workspace'in → **Create App**
4. Sol menü → **OAuth & Permissions**
   - Aşağı kaydır → **Scopes** bölümü → **Bot Token Scopes**
   - **Add an OAuth Scope** → `files:write` ekle
   - (Opsiyonel) `chat:write` da ekle (önerilir; bazı Slack edge
     case'leri için)
5. Sol menü → **App Home**
   - **Your App's Presence in Slack** → **Edit** butonuyla bot
     display name'i set et (örn. `mersel-dss-signer-notify`)
6. Sol menü → **Install App** → **Install to Workspace**
   - Slack onay ekranı → **Allow**
7. **Bot User OAuth Token** (`xoxb-...`) görünür → **Copy**

---

#### 9.2 Kanal ID'sini bulma (3 yöntem; en kolayı 1.)

**Yöntem 1 — Slack desktop UI** (en hızlı):

1. Slack uygulamasında alarm gitmesini istediğin kanala git
2. Kanal başlığına tıkla (en üstte kanal adının olduğu yer)
3. Açılan paneli en aşağı kaydır
4. **Channel ID** alanı görünür: `C0123ABCD45` formatında →
   **Copy** butonuna tıkla

**Yöntem 2 — Slack web URL'inden**:

Slack'i tarayıcıda aç, kanala tıkla. URL şu şekilde olur:

```
https://app.slack.com/client/T01234ABCD/C0123ABCD45
                              ^team-id  ^channel-id (bu sana lazım)
```

URL'in son segmenti kanal ID'sidir.

**Yöntem 3 — Slack API çağrısı** (otomasyon için):

```bash
curl -X GET 'https://slack.com/api/conversations.list?limit=200' \
  -H "Authorization: Bearer xoxb-..." | jq '.channels[] | {name, id}'
```

---

#### 9.3 Kanala bot'u ekleme (kritik adım!)

Bot, mesaj atacağı / dosya yükleyeceği kanala **explicit olarak davet
edilmelidir** (Slack'in güvenlik modeli). Davet etmezsen
`step1 reddedildi: not_in_channel` hatasını alırsın.

Slack desktop UI'da hedef kanala git ve mesaj kutusuna yaz:

```
/invite @mersel-dss-signer-notify
```

(Bot ismini App Manifest'te yazdığın `bot_user.display_name` değeri
olarak yazıyorsun — manifest yöntemiyle yukarıda
`mersel-dss-signer-notify` demiştik.)

Slack onaylar; bot artık kanalda. Test için kanal mesaj kutusuna
`@mersel-dss-signer-notify` yazıp Tab'a basabilirsin — autocomplete
gösterirse bot kanaldadır.

---

#### 9.4 Kurulumu doğrula (smoke test)

Bot token + kanal ID'sini set ettiğin yerden manuel olarak Slack
API'sını çağırıp test edebilirsin:

```bash
# Sadece auth çalışıyor mu test et (hiçbir kanala yazmaz):
curl -X POST https://slack.com/api/auth.test \
  -H "Authorization: Bearer xoxb-..." \
  -H "Content-Type: application/json; charset=utf-8"

# Beklenen yanıt:
# {"ok":true,"url":"...","team":"...","user":"mersel-dss-signer-notify",...}

# files:write scope çalışıyor mu test et:
curl -X POST 'https://slack.com/api/files.getUploadURLExternal' \
  -H "Authorization: Bearer xoxb-..." \
  --data-urlencode "filename=test.txt" \
  --data-urlencode "length=4"

# Beklenen yanıt: {"ok":true,"upload_url":"...","file_id":"..."}
# Eğer "missing_scope" donerse YÖNTEM A/B adım 4'e geri don.
```

Smoke test geçtiyse env'leri set et ve Mersel DSS Signer API'yi
restart et:

```bash
export SIGNER_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T0/B0/XXX
export SIGNER_SLACK_BOT_TOKEN=xoxb-...
export SIGNER_SLACK_CHANNEL=C0123ABCD45
```

İlk imza hatasında Slack kanalında **kırmızı bantlı alarm mesajı +
indirilebilir dosya** görmelisin. Bir test akışı:

```bash
# Yanlış formatta hash gönder — controller exception fırlatır,
# notifier signature-failure event'i tetikler:
curl -X POST http://localhost:8085/v1/hashsign \
  -H "Content-Type: application/json" \
  -H "x-log-id: smoke-test-$(date +%s)" \
  -d '{"base64EncodedDigest":"INVALID","digestAlgorithm":"SHA256"}'
```

Beklenen sonuç:
- HTTP 400 (controller `INVALID_INPUT` döner — bu IllegalArgumentException
  olduğu için bildirim üretmez; gürültü kontrolü gereği. Bildirim almak
  için `SignatureException` veya generic 500 üreten bir akış kullanın.)

Asıl smoke için: HSM bağlantısını koparın veya yanlış token ile
gerçek bir XAdES request'i yapın — 500 yanıt + Slack alarmı görün.

---

#### 9.5 Bot kuramıyorum / IT politikası izin vermiyor — alternatifler

| Senaryo | Çözüm |
|---|---|
| Admin "Apps must be approved" → app pending | Admin'e bu HOW_TO_USE'un manifest YAML'ını gönder, onay 5 dakika alır. App private + read-only (`files:write`), risk düşük |
| Workspace policy hiçbir bot'a izin vermiyor | Section 8 — **Slack-only inline base64** kullan. Dosyaların ≤28KB'sa direkt mesajda görünür, bot/scope yok. Not: heartbeat alarmları için bot kurulumu zaten gerekmez (heartbeat metadata-only) |
| Workspace policy katı + dosyalar 250KB+ | Generic webhook + kendi sisteminize base64 receiver. Bu Slack'in dışı — eğer Slack zorunluysa IT'ye manifest sunulup approve ettirilmesi gerek |

### 9.6 Boyut sınırı

Dosya `SIGNER_NOTIFICATION_MAX_CONTENT_SIZE_BYTES` (default 10MB)
üstündeyse Slack upload **atlanır** (`info` log'u düşer). Webhook
payload'ı yine gönderilir (metadata + omitted reason ile). Slack'in
kendi sert dosya limiti ise **1GB** — pratikte hiç vurmazsın.

---

## 10. Gizlilik & güvenlik

| Risk | Önlem |
|---|---|
| Mali Mühür PDF içinde VKN / TCKN | `SIGNER_NOTIFICATION_INCLUDE_CONTENT=false` → sadece metadata gider |
| HSM hata mesajlarında PIN leak'i | `SignatureException` mesajları üretirken PIN bilgisi loglanmaz (security policy); generic `Exception.getMessage()` için kod review şart |
| Receiver dışındaki birinin alert URL'i keşfetmesi | `SIGNER_WEBHOOK_SECRET` set et — HMAC olmadan istek reddedilir |
| Receiver eski bildirimi replay etmesi | Timestamp 5 dakika penceresi + `Webhook-Id` ile DB tarafında dedupe |
| Slack bot token leak | Sadece `files:write` + `chat:write` scope ver, başka scope verme |
| `x-log-*` header'larında PII | Filter `MAX_VALUE_LENGTH=512` ile kırpıyor + CR/LF temizliyor; ama upstream gateway'in `x-log-tckn` benzeri hassas başlık göndermediğinden emin ol |
| Chat'te alarm taşması | Default 10 x-log header + 5 hata Slack mesajına taşınır, kalanı webhook payload'ına |

---

## 11. Operasyonel davranış

- **Async + best-effort** — `notifyOnSignatureFailure()` ve
  `notifyOnHeartbeatEvent()` çağrıları thread'i bloklamaz; OkHttp
  `enqueue()` ile arka plana atılır.
- **Bildirim hatası imza akışını bozmaz** — receiver 500 dönse, URL
  ölü olsa, token yanlış olsa: hep WARN log'u + akış devam.
- **Gerçek sıfır overhead** — `SIGNER_NOTIFICATION_ENABLED=false`
  VEYA hiçbir destination env var'ı set edilmemişse `@PostConstruct`
  **OkHttpClient bile yaratmaz** (dispatcher thread pool + connection
  pool yok). Yalnız bean'in iki primitive field'ı yaşar (~birkaç
  byte). Bu sayede notification feature kapalıyken servisin
  steady-state heap kullanımı bu modülden etkilenmez.
- **Heartbeat scheduler entegrasyonu** — `HsmHeartbeatScheduler`
  `@ConditionalOnExpression` ile sadece `PKCS11_LIBRARY` set'liyken
  yüklenir. Notifier her zaman yüklenir; HSM yoksa `heartbeatEnabled`
  flag'i etkisizdir (üretilen event yok).
- **x-log-* MDC capture (sync-only)** — Notifier'ın sync kısmında
  (controller/scheduler thread'inde) MDC snapshot alınır; async OkHttp
  dispatcher thread'ine güvenle taşınır. `@Async` veya executor
  dispatch'inde MDC kaybolur — yeni async kullanım eklerken
  `MDC.getCopyOfContextMap()` ile manuel taşıma gerekir.
- **Retry yok** — webhook receiver'ı kendi tarafında idempotent
  almalı (`X-Mersel-Webhook-Id` ile DB-side dedupe). Daha agresif SLA
  için outbox pattern + retry queue'yu receiver tarafında kurmalısınız.
- **Heartbeat gürültü kontrolü** — Section 2.2'de detaylanan
  transition-based bildirim mantığı: her tick'te değil; sadece
  state change'lerde ve ERROR eşik aşımının ilk anında. Üretimde
  gözlenen 3297× ardışık fail incident'i bu kuralı doğurdu.

---

## 12. Sorun giderme

### 12.1 Webhook-tarafı sorunlar

| Belirti | Olası neden |
|---|---|
| `webhook POST non-2xx: 401` | Secret eşleşmiyor — receiver tarafında secret değiştir |
| `webhook POST non-2xx: 422` | Receiver payload schema'sını parse edemiyor — `event` discriminator'a göre dispatch yapılıyor mu kontrol et |
| `webhook POST başarısız: Failed to connect` | Receiver ayakta değil veya firewall — telnet ile doğrula |
| `webhook: URL geçersiz` | URL `http://` / `https://` ile başlamıyor veya bozuk format |

### 12.2 Slack incoming webhook sorunları

| Belirti | Olası neden |
|---|---|
| Slack mesajı geliyor ama renk yok | Slack mobil/desktop'ta attachment color render legacy field; mobil uygulamayı güncelle |
| Mesajda "boyut limit aşıyor" notice'i ama dosya gelmedi | `SIGNER_SLACK_INLINE_BASE64_MAX_BYTES` çok küçük — dosya boyutuna göre artırın (Slack mesaj toplam 40KB limitini aşmayın → binary ≤28KB önerilir) veya bot upload'a geçin |
| Inline base64 enable ama mesajda code block görünmüyor | `SIGNER_SLACK_INLINE_BASE64_ENABLED=true` mu? `enabled=false`'da hiç eklenmez. Heartbeat event'i ise: dosya yok, kontrat gereği eklenmez |
| Decode edilen dosya bozuk | Multi-chunk durumda tüm code block'ları sıralı concat ettiğinizden emin olun (Slack mesaj sırası = chunk sırası); arada whitespace olmasın |

### 12.3 Slack bot file upload sorunları

| Belirti | Olası neden |
|---|---|
| `step1 reddedildi: invalid_auth` | Token yanlış kopyalanmış — `xoxb-...` ile başlamalı, `xapp-` veya `xoxe-` değil. **OAuth & Permissions** → **Bot User OAuth Token** alanını tekrar kopyala |
| `step1 reddedildi: token_revoked` | App kaldırılmış veya admin tarafından devre dışı bırakılmış — Slack admin'i ile konuş, yeniden install et |
| `step1 reddedildi: not_in_channel` | Bot kanala davet edilmemiş. Kanalda `/invite @mersel-dss-signer-notify` yaz |
| `step1 reddedildi: missing_scope` | Bot user OAuth scopes'a `files:write` ekleyin → workspace'e **yeniden** install edin (scope ekleyince re-install zorunlu) |
| `step1 reddedildi: channel_not_found` | `SIGNER_SLACK_CHANNEL` yanlış format — kanal **adı** değil **ID** (`C` ile başlayan ~10 char). Kanal başlığına tıkla → en altta görünür |
| `step1 reddedildi: ratelimited` | Slack API'sini hızlı çağırıyorsun (Tier 4 = 100+/dk). Signer rate'i normalde altında; gerçekten 100+ signature-failure/dakika düşüyorsa altyapı sorunu vardır |
| Slack mesajı geliyor ama dosya gelmiyor | `SIGNER_SLACK_CHANNEL` ID değil, ad set edilmiş — `C…` formatına çevir |
| Heartbeat event'inde dosya gelmiyor | Beklenen davranış — heartbeat'in dosyası yoktur (kontrat) |

### 12.4 Heartbeat bildirim sorunları

| Belirti | Olası neden |
|---|---|
| HSM aşağıda ama hiç `heartbeat-failed` gelmiyor | `HSM_HEARTBEAT_ENABLED=true` ve `PKCS11_LIBRARY` set'li mi? Scheduler `@ConditionalOnExpression` ile yüklenir |
| Her tick'te `heartbeat-failed` geliyor (spam) | Beklenmiyor — kod sadece `consecutive==1` ve `consecutive==5`'te bildirir. Versiyonu kontrol et (`/actuator/info`) |
| `heartbeat-recovered` hiç gelmiyor | Recovery sadece *transition'da* (önce ardışık fail vardı → şimdi başarı). İlk başlangıçta success row'unda bildirim yok |
| Heartbeat event'leri geliyor ama signature-failure gelmiyor | `SIGNER_NOTIFICATION_SIGNATURE_FAILURE_ENABLED` false olabilir; veya signature endpoint'leri SignatureException dışı bir exception fırlatıyor (yine bildirilmeli — log'lara bak) |

### 12.5 x-log-* header sorunları

| Belirti | Olası neden |
|---|---|
| Webhook payload'unda `logHeaders` null | Request thread'inde gelen `x-log-*` header yok — gateway/proxy bunu strip ediyor mu? Veya bildirim heartbeat scheduler thread'inden (request bağlamı yok) |
| Slack mesajında x-log- korelasyon bloğu yok | Aynı sebep — request bağlamı yoksa blok eklenmez (gürültü olmasın diye) |
| Bazı `x-log-*` header'lar payload'a düşmüyor | `LogHeadersFilter.MAX_HEADERS=20` üst sınırı var; 20'den fazla header'lar drop edilir. Veya değer boş/sadece whitespace |
| `x-log-*` değer truncate olmuş | Filter `MAX_VALUE_LENGTH=512` karakterden sonra kırpıyor — bu güvenlik kuralı (log injection / büyük payload DOS koruması) |

---

## 13. Pazardaki yerleşik çözümlerle karşılaştırma

Pazardaki bulut tabanlı muhasebe / e-Belge oyuncuları imza başarısızlığı
veya HSM problemi tespit ettiğinde:

- **Yerleşik bulut çözümleri** — UI bildirimi veya günlük raporlar;
  mükellef genelde ertesi iş gününde fark eder. HSM down olduğunda
  müşteri 99+ dakika "tetik patlamayan" istekleri beklemek zorunda
  kalır (üretim incident'inden öğrenildi).
- **Mersel DSS Signer** — Olay anında olay-tabanlı bildirim:
  - Tespit süresi saatlerden **saniyelere** iner.
  - HMAC + delivery-id ile **bildirimden idempotency'ye kadar** denetim
    ekibinin VUK Madde 227 + e-defter saklama kurallarına uygun kanıt
    zinciri kurabileceği bir audit topology sunar.
  - HSM heartbeat self-healing state machine + transition bildirimi,
    operasyon ekibinin secure channel teardown gibi infrastructure
    seviyesi sorunlara saniyeler içinde reaktif olabilmesini sağlar.
  - Slack renk-kodlu mesaj + indirilebilir dosya kombosu, muhasebe ve
    DevOps ekibinin RDP'siz / VPN'siz işle aksiyon almasını mümkün
    kılar — yerleşik çözümlerde her durumda web paneline login
    zorunluluğu vardır.

---

## 14. Ek: Tam env değişkenleri referansı

```bash
# --- Master ---
SIGNER_NOTIFICATION_ENABLED=true                  # default; false = topyekun susturma

# --- Event-seviye flag'ler ---
SIGNER_NOTIFICATION_SIGNATURE_FAILURE_ENABLED=true # default
SIGNER_NOTIFICATION_HEARTBEAT_ENABLED=true         # default

# --- Generic webhook ---
SIGNER_WEBHOOK_URL=                                # boş = devre dışı
SIGNER_WEBHOOK_SECRET=                             # HMAC için; boş = imza yok

# --- Slack incoming webhook ---
SIGNER_SLACK_WEBHOOK_URL=                          # boş = devre dışı

# --- Slack bot file upload ---
SIGNER_SLACK_BOT_TOKEN=                            # xoxb-...; boş VEYA channel boşsa devre dışı
SIGNER_SLACK_CHANNEL=                              # C0123ABCD45 (ID, ad değil)

# --- Slack inline base64 fallback (single-URL mod) ---
SIGNER_SLACK_INLINE_BASE64_ENABLED=false           # default; opt-in
SIGNER_SLACK_INLINE_BASE64_MAX_BYTES=8192          # default 8KB; max ~28000 güvenli

# --- İçerik / boyut ---
SIGNER_NOTIFICATION_INCLUDE_CONTENT=true           # default; PII için false
SIGNER_NOTIFICATION_MAX_CONTENT_SIZE_BYTES=10485760 # default 10MB

# --- HTTP timeouts ---
SIGNER_NOTIFICATION_CONNECT_TIMEOUT_MS=5000        # default 5s
SIGNER_NOTIFICATION_READ_TIMEOUT_MS=10000          # default 10s
```

Tüm değişkenler aynı zamanda `application.properties` üzerinden
`notification.signer.*` formatında da set edilebilir:

```properties
notification.signer.enabled=true
notification.signer.events.signature-failure.enabled=true
notification.signer.events.heartbeat.enabled=true
notification.signer.webhook.url=https://alerts.example.com/hooks/signer
notification.signer.webhook.secret=...
notification.signer.slack.webhook.url=https://hooks.slack.com/services/...
notification.signer.slack.bot.token=xoxb-...
notification.signer.slack.bot.channel=C0123ABCD45
notification.signer.slack.inline-base64-enabled=false
notification.signer.slack.inline-base64-max-bytes=8192
notification.signer.include-content=true
notification.signer.max-content-size-bytes=10485760
notification.signer.connect-timeout-ms=5000
notification.signer.read-timeout-ms=10000
```

Spring Boot precedence: OS env > JVM `-D` > `application.properties`
> profile-specific overrides.
