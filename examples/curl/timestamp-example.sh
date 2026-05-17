#!/bin/bash

# Zaman Damgası (Timestamp) Kullanım Örnekleri
# RFC 3161 standardına uygun timestamp alma ve doğrulama
# Multipart/form-data ile dosya yükleme

set -e

BASE_URL="http://localhost:8080"
API_URL="${BASE_URL}/api/timestamp"

# Renkli çıktı için
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=================================="
echo "Timestamp API Kullanım Örnekleri"
echo "Multipart/Form-Data"
echo "=================================="
echo ""

# 1. Servis durumunu kontrol et
echo -e "${YELLOW}1. Timestamp servisi durumunu kontrol et${NC}"
echo "-----------------------------------"
STATUS=$(curl -s "${API_URL}/status")
echo "$STATUS" | jq .

if [ "$(echo "$STATUS" | jq -r '.configured')" != "true" ]; then
    echo -e "${RED}HATA: Timestamp servisi yapılandırılmamış!${NC}"
    echo "Lütfen TS_SERVER_HOST ortam değişkenini ayarlayın."
    exit 1
fi
echo -e "${GREEN}✓ Servis aktif${NC}"
echo ""

# 2. Test dosyası oluştur
echo -e "${YELLOW}2. Test dosyası oluştur${NC}"
echo "-----------------------------------"
TEST_FILE="/tmp/test_document.txt"
echo "Bu bir test belgesidir - $(date)" > "$TEST_FILE"
echo "Dosya oluşturuldu: $TEST_FILE"
echo "İçerik: $(cat "$TEST_FILE")"
echo ""

# 3. Dosya için timestamp al (binary response)
echo -e "${YELLOW}3. Dosya için timestamp al (binary .tst)${NC}"
echo "-----------------------------------"

TST_FILE="/tmp/timestamp_token.tst"
HEADERS_FILE="/tmp/timestamp_headers.txt"

# Binary response + header'lar
HTTP_CODE=$(curl -s -w "%{http_code}" -X POST "${API_URL}/get" \
  -F "document=@$TEST_FILE" \
  -F "hashAlgorithm=SHA256" \
  -o "$TST_FILE" \
  -D "$HEADERS_FILE")

if [ "$HTTP_CODE" = "200" ]; then
    # Metadata header'lardan oku
    TS_TIME=$(grep -i "X-Timestamp-Time:" "$HEADERS_FILE" | cut -d' ' -f2- | tr -d '\r')
    TSA_NAME=$(grep -i "X-Timestamp-TSA:" "$HEADERS_FILE" | cut -d' ' -f2- | tr -d '\r')
    SERIAL=$(grep -i "X-Timestamp-Serial:" "$HEADERS_FILE" | cut -d' ' -f2- | tr -d '\r')
    HASH_ALG=$(grep -i "X-Timestamp-Hash-Algorithm:" "$HEADERS_FILE" | cut -d' ' -f2- | tr -d '\r')
    
    echo -e "${GREEN}✓ Timestamp başarıyla alındı (binary)${NC}"
    echo "Dosya: $TST_FILE"
    echo "Boyut: $(wc -c < "$TST_FILE") bytes"
    echo ""
    echo "Metadata (header'lardan):"
    echo "  Zaman: $TS_TIME"
    echo "  TSA: $TSA_NAME"
    echo "  Serial: $SERIAL"
    echo "  Hash: $HASH_ALG"
else
    echo -e "${RED}✗ Timestamp alınamadı (HTTP $HTTP_CODE)${NC}"
    cat "$TST_FILE"
    exit 1
fi
echo ""

# 4. Timestamp'i doğrula (orijinal dosya ile)
echo -e "${YELLOW}4. Timestamp'i doğrula (orijinal dosya ile)${NC}"
echo "-----------------------------------"
VALIDATION_RESPONSE=$(curl -s -X POST "${API_URL}/validate" \
  -F "timestampToken=@$TST_FILE" \
  -F "originalDocument=@$TEST_FILE")

echo "$VALIDATION_RESPONSE" | jq .

IS_VALID=$(echo "$VALIDATION_RESPONSE" | jq -r '.valid')
HASH_VERIFIED=$(echo "$VALIDATION_RESPONSE" | jq -r '.hashVerified')
MESSAGE=$(echo "$VALIDATION_RESPONSE" | jq -r '.message')

if [ "$IS_VALID" = "true" ]; then
    echo -e "${GREEN}✓ Timestamp geçerli${NC}"
    if [ "$HASH_VERIFIED" = "true" ]; then
        echo -e "${GREEN}✓ Hash doğrulandı - belge değişmemiş${NC}"
    fi
else
    echo -e "${RED}✗ Timestamp geçersiz${NC}"
    echo "Mesaj: $MESSAGE"
fi
echo ""

# 5. Timestamp'i doğrula (sadece token ile)
echo -e "${YELLOW}5. Timestamp'i doğrula (sadece token ile)${NC}"
echo "-----------------------------------"
VALIDATION_RESPONSE_NO_DATA=$(curl -s -X POST "${API_URL}/validate" \
  -F "timestampToken=@$TST_FILE")

echo "$VALIDATION_RESPONSE_NO_DATA" | jq .

IS_VALID_NO_DATA=$(echo "$VALIDATION_RESPONSE_NO_DATA" | jq -r '.valid')

if [ "$IS_VALID_NO_DATA" = "true" ]; then
    echo -e "${GREEN}✓ Timestamp yapısı geçerli${NC}"
    echo "Not: Orijinal dosya sağlanmadığı için hash doğrulaması yapılmadı"
else
    echo -e "${RED}✗ Timestamp geçersiz${NC}"
fi
echo ""

# 6. XML dosyası için timestamp örneği (eğer örnek dosya varsa)
# Fixture'lar 0.3+ sonrası resources/test-fixtures/xades/ altında.
if [ -f "../../resources/test-fixtures/xades/efatura.xml" ]; then
    echo -e "${YELLOW}6. XML dosyası için timestamp al${NC}"
    echo "-----------------------------------"
    
    XML_FILE="../../resources/test-fixtures/xades/efatura.xml"
    XML_TST_FILE="/tmp/xml_timestamp_token.tst"
    
    HTTP_CODE=$(curl -s -w "%{http_code}" -X POST "${API_URL}/get" \
      -F "document=@$XML_FILE" \
      -F "hashAlgorithm=SHA256" \
      -o "$XML_TST_FILE" \
      -D "$HEADERS_FILE")
    
    if [ "$HTTP_CODE" = "200" ]; then
        echo -e "${GREEN}✓ XML dosyası için timestamp alındı${NC}"
        
        # Dosya timestamp'ini doğrula
        FILE_VALIDATION=$(curl -s -X POST "${API_URL}/validate" \
          -F "timestampToken=@$XML_TST_FILE" \
          -F "originalDocument=@$XML_FILE")
        
        FILE_IS_VALID=$(echo "$FILE_VALIDATION" | jq -r '.valid')
        if [ "$FILE_IS_VALID" = "true" ]; then
            echo -e "${GREEN}✓ XML dosyası timestamp'i doğrulandı${NC}"
        else
            echo -e "${RED}✗ XML dosyası timestamp'i doğrulanamadı${NC}"
        fi
    else
        echo -e "${RED}✗ XML dosyası için timestamp alınamadı${NC}"
    fi
    echo ""
fi

# 7. Farklı hash algoritmaları ile test
echo -e "${YELLOW}7. Farklı hash algoritmaları ile test${NC}"
echo "-----------------------------------"

for HASH_ALG in "SHA256" "SHA384" "SHA512"; do
    echo "Test ediliyor: $HASH_ALG"
    
    TMP_TST="/tmp/test_${HASH_ALG}.tst"
    HTTP_CODE=$(curl -s -w "%{http_code}" -X POST "${API_URL}/get" \
      -F "document=@$TEST_FILE" \
      -F "hashAlgorithm=$HASH_ALG" \
      -o "$TMP_TST")
    
    if [ "$HTTP_CODE" = "200" ] && [ -s "$TMP_TST" ]; then
        echo -e "  ${GREEN}✓ $HASH_ALG başarılı ($(wc -c < "$TMP_TST") bytes)${NC}"
    else
        echo -e "  ${RED}✗ $HASH_ALG başarısız${NC}"
    fi
done
echo ""

# 8. Değiştirilmiş dosya ile doğrulama testi
echo -e "${YELLOW}8. Değiştirilmiş dosya ile doğrulama testi${NC}"
echo "-----------------------------------"

# Dosyayı değiştir
MODIFIED_FILE="/tmp/modified_document.txt"
echo "Değiştirilmiş içerik" > "$MODIFIED_FILE"

echo "Değiştirilmiş dosya ile eski timestamp'i doğrula..."
MODIFIED_VALIDATION=$(curl -s -X POST "${API_URL}/validate" \
  -F "timestampToken=@$TST_FILE" \
  -F "originalDocument=@$MODIFIED_FILE")

MODIFIED_VALID=$(echo "$MODIFIED_VALIDATION" | jq -r '.valid')
MODIFIED_HASH=$(echo "$MODIFIED_VALIDATION" | jq -r '.hashVerified')

if [ "$MODIFIED_HASH" = "false" ]; then
    echo -e "${GREEN}✓ Dosya değişikliği doğru şekilde tespit edildi${NC}"
else
    echo -e "${RED}✗ Dosya değişikliği tespit edilemedi${NC}"
fi
echo ""

# 9. Geçersiz token ile doğrulama testi
echo -e "${YELLOW}9. Geçersiz token ile doğrulama testi${NC}"
echo "-----------------------------------"

# Geçersiz bir token dosyası oluştur
INVALID_TST="/tmp/invalid_token.tst"
echo "invalid_token_data" > "$INVALID_TST"

INVALID_VALIDATION=$(curl -s -X POST "${API_URL}/validate" \
  -F "timestampToken=@$INVALID_TST")

INVALID_IS_VALID=$(echo "$INVALID_VALIDATION" | jq -r '.valid')

if [ "$INVALID_IS_VALID" = "false" ]; then
    echo -e "${GREEN}✓ Geçersiz token doğru şekilde reddedildi${NC}"
else
    echo -e "${RED}✗ Geçersiz token kabul edildi (beklenmeyen)${NC}"
fi
echo ""

# Özet
echo "=================================="
echo "Test Özeti"
echo "=================================="
echo -e "${GREEN}✓ Tüm testler tamamlandı${NC}"
echo ""
echo "Oluşturulan dosyalar:"
echo "  - $TEST_FILE (test belgesi)"
echo "  - $TST_FILE (timestamp token)"
if [ -f "$XML_TST_FILE" ]; then
    echo "  - $XML_TST_FILE (XML timestamp token)"
fi
echo ""
echo "Bu token'ları daha sonra doğrulamak için kullanabilirsiniz:"
echo "  curl -X POST ${API_URL}/validate \\"
echo "    -F \"timestampToken=@$TST_FILE\" \\"
echo "    -F \"originalDocument=@$TEST_FILE\""
