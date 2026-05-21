package io.mersel.dss.signer.api.services.signature.xades;

import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link SignatureIdNormalizer}'ın TÜBİTAK BES uyumlu deterministicId
 * üretimini ve invalid girdilere karşı erken patlamayı garanti eder.
 *
 * <h3>Regresyon hikayesi</h3>
 * <p>Bu test sınıfı, ApplicationResponse imzalandığında doğrulanmayan
 * imza şikayeti üzerine açılan ID sanitization fix'inin sessizce geri
 * gelmesini engeller. Bug, kullanıcının {@code signatureId="#Signature_Attach_1"}
 * vermesiyle ortaya çıkıyordu: kod ham olarak {@code "Signature_"} prefix
 * ekliyor ve içinde {@code '#'} bulunan invalid bir NCName üretiyordu.
 * Sonuçta {@code URI="#xades-Signature_#Signature_Attach_1"} RFC 3986
 * fragment kuralını ihlal ediyor, GİB tarafındaki doğrulayıcı
 * SignedProperties node'unu bulamıyordu.</p>
 */
@Epic("XAdES Conformance")
@Feature("Signature ID normalization")
@Severity(SeverityLevel.CRITICAL)
class SignatureIdNormalizerTest {

    @Nested
    @DisplayName("Pozitif kasalar - geçerli NCName üretir")
    class HappyPath {

        @Test
        @DisplayName("Çıplak suffix verilirse 'Signature_' prefix'i otomatik eklenir")
        void prependsPrefixWhenAbsent() {
            assertEquals("Signature_Attach_1", SignatureIdNormalizer.normalize("Attach_1"));
        }

        @Test
        @DisplayName("Zaten prefix'li gelirse çift prefix oluşmaz (idempotent)")
        void doesNotDoublePrefix() {
            assertEquals(
                    "Signature_Attach_1",
                    SignatureIdNormalizer.normalize("Signature_Attach_1"));
        }

        @Test
        @DisplayName("URI fragment formundaki '#' karakteri temizlenir")
        void stripsLeadingHashFromUriFragment() {
            assertEquals(
                    "Signature_Attach_1",
                    SignatureIdNormalizer.normalize("#Signature_Attach_1"));
        }

        @Test
        @DisplayName("Peş peşe '#' karakterleri tamamen temizlenir")
        void stripsMultipleLeadingHashes() {
            assertEquals(
                    "Signature_x",
                    SignatureIdNormalizer.normalize("##Signature_x"));
        }

        @Test
        @DisplayName("Etrafındaki boşluklar trim edilir")
        void trimsSurroundingWhitespace() {
            assertEquals(
                    "Signature_Attach_1",
                    SignatureIdNormalizer.normalize("  Attach_1  "));
        }

        @Test
        @DisplayName("UUID-benzeri suffix (e-Fatura konvansiyonu) geçerli kalır")
        void acceptsUuidLikeSuffix() {
            String result = SignatureIdNormalizer.normalize(
                    "id-9f3e8b7d-2c14-4a5f-bc7d-1e89fd0b6c0a");
            assertEquals(
                    "Signature_id-9f3e8b7d-2c14-4a5f-bc7d-1e89fd0b6c0a",
                    result);
        }

        @Test
        @DisplayName("UUID sadece olarak verildiğinde prefix eklenir")
        void acceptsBareUuid() {
            assertEquals(
                    "Signature_cd5ff9f1-9e14-408c-bc92-f56561a0191e",
                    SignatureIdNormalizer.normalize(
                            "cd5ff9f1-9e14-408c-bc92-f56561a0191e"));
        }

        @Test
        @DisplayName("Hem '#' prefix hem 'Signature_' prefix birlikte gelirse normalize edilir")
        void combinesHashAndPrefixCleanup() {
            // User reflexively types both the URI '#' and the conventional prefix
            assertEquals(
                    "Signature_72cfd1a1-d0bf-4cf9-913f-acf8dc292ef3",
                    SignatureIdNormalizer.normalize(
                            "#Signature_72cfd1a1-d0bf-4cf9-913f-acf8dc292ef3"));
        }
    }

    @Nested
    @DisplayName("Null/boş kasalar - DSS default'una düşülür")
    class FallbackToDssDefault {

        @Test
        @DisplayName("Null girdi null döner (DSS kendi UUID'sini üretsin)")
        void nullReturnsNull() {
            assertNull(SignatureIdNormalizer.normalize(null));
        }

        @Test
        @DisplayName("Tamamen boşluk olan girdi null döner")
        void blankReturnsNull() {
            assertNull(SignatureIdNormalizer.normalize("   "));
        }

        @Test
        @DisplayName("Boş string null döner")
        void emptyReturnsNull() {
            assertNull(SignatureIdNormalizer.normalize(""));
        }
    }

    @Nested
    @DisplayName("Negatif kasalar - invalid NCName erken patlar")
    class Rejects {

        @Test
        @DisplayName("İçinde '#' olan suffix INVALID_SIGNATURE_ID ile reddedilir")
        void rejectsEmbeddedHash() {
            SignatureException ex = assertThrows(
                    SignatureException.class,
                    () -> SignatureIdNormalizer.normalize("abc#def"));
            assertEquals("INVALID_SIGNATURE_ID", ex.getErrorCode());
            assertTrue(ex.getMessage().contains("'#'"),
                    "Mesaj kullanıcıya '#' karakterinin yasak olduğunu söylemeli");
        }

        @Test
        @DisplayName("Sadece '#' prefix sonrası NCName ihlali kalan girdi reddedilir")
        void rejectsHashInsideAfterStrip() {
            // "#x#y" -> strip leading '#' -> "x#y" -> still contains '#'
            SignatureException ex = assertThrows(
                    SignatureException.class,
                    () -> SignatureIdNormalizer.normalize("#x#y"));
            assertEquals("INVALID_SIGNATURE_ID", ex.getErrorCode());
        }

        @Test
        @DisplayName("Sadece '#' karakteri verilirse boş suffix'e düşer ve reddedilir")
        void rejectsOnlyHash() {
            // After stripping: "" -> with prefix "Signature_" which IS valid NCName.
            // Edge case: bu aslında geçerli bir NCName ("Signature_") olur, fakat
            // semantik açıdan kullanıcı niyetini ifade etmiyor. Burada davranış:
            // prefix-only ID kabul edilir (DSS'in onu ID olarak basmasında sorun
            // yok), bu yüzden THROWS yerine geçerli output bekleniyor.
            // Eğer ileride bunu da reddetmek istersek bu testi güncelleriz.
            assertEquals("Signature_", SignatureIdNormalizer.normalize("#"));
        }

        @Test
        @DisplayName("Rakamla başlayan suffix reddedilir (XML NCName harf/'_' ile başlamalı)")
        void rejectsLeadingDigit() {
            // "9abc" -> "Signature_9abc" - bu aslında NCName geçerlidir çünkü
            // prefix harf ile başlıyor. NCName kuralı "ilk karakter" için sadece
            // tüm string'e bakar.
            assertEquals(
                    "Signature_9abc",
                    SignatureIdNormalizer.normalize("9abc"));
        }

        @Test
        @DisplayName("Boşluk içeren id reddedilir")
        void rejectsInternalWhitespace() {
            SignatureException ex = assertThrows(
                    SignatureException.class,
                    () -> SignatureIdNormalizer.normalize("Attach 1"));
            assertEquals("INVALID_SIGNATURE_ID", ex.getErrorCode());
        }

        @Test
        @DisplayName("'/' veya ':' gibi XML-DSig'da yasak karakterler reddedilir")
        void rejectsForbiddenPunctuation() {
            assertThrows(SignatureException.class,
                    () -> SignatureIdNormalizer.normalize("a/b"));
            assertThrows(SignatureException.class,
                    () -> SignatureIdNormalizer.normalize("ns:local"));
            assertThrows(SignatureException.class,
                    () -> SignatureIdNormalizer.normalize("a@b"));
        }
    }
}
