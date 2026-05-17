package io.mersel.dss.signer.api.services.keystore.iaik;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;

/**
 * {@link IaikPkcs11Module#findByIdOrLabel} ve cert↔private key bağlama
 * akışı için güvenlik regresyon testleri.
 *
 * <h2>Korunan vakalar</h2>
 * <ul>
 *   <li><b>Duplicate CKA_LABEL</b> + key rotation: yanlış key cert'e bağlanmamalı.</li>
 *   <li><b>CKA_ID present</b>: label fallback ASLA yapılmamalı (ID-only).</li>
 *   <li><b>CKA_ID absent + tek-eşleşme</b>: label fallback yapılır.</li>
 *   <li><b>CKA_ID absent + birden fazla label match</b>: ambiguous → null.</li>
 * </ul>
 *
 * <p>Bu testler {@code TokenObject} ve {@code findByIdOrLabel} reflective
 * olarak erişir — bu yüzler API olarak public değil ama davranış kontratı
 * production güvenliği için kritik.</p>
 */
class IaikPkcs11ModuleKeyBindingTest {

    private static Class<?> tokenObjectClass;
    private static Method findByIdOrLabel;

    static {
        try {
            for (Class<?> nested : IaikPkcs11Module.class.getDeclaredClasses()) {
                if (nested.getSimpleName().equals("TokenObject")) {
                    tokenObjectClass = nested;
                    break;
                }
            }
            findByIdOrLabel = IaikPkcs11Module.class.getDeclaredMethod(
                "findByIdOrLabel", List.class, byte[].class, String.class, boolean.class);
            findByIdOrLabel.setAccessible(true);
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException(e);
        }
    }

    // ---- Test fixture helpers ----

    private static Object newTokenObject(String label, byte[] id,
                                         /* nullable */ X509Certificate cert, long privateKeyHandle) throws Exception {
        Constructor<?> ctor = tokenObjectClass.getDeclaredConstructor();
        ctor.setAccessible(true);
        Object to = ctor.newInstance();
        setField(to, "label", label);
        setField(to, "id", id);
        setField(to, "cert", cert);
        setField(to, "privateKeyHandle", privateKeyHandle);
        return to;
    }

    private static void setField(Object instance, String name, Object value) throws Exception {
        Field f = tokenObjectClass.getDeclaredField(name);
        f.setAccessible(true);
        f.set(instance, value);
    }

    @SuppressWarnings("unchecked")
    private static <T> T find(List<?> objects, byte[] id, String label, boolean preferCertSide) throws Exception {
        return (T) findByIdOrLabel.invoke(null, objects, id, label, preferCertSide);
    }

    /**
     * Cert tarafı için minimal X509Certificate stand-in.
     * Davranış değil, sadece "cert != null" sinyali önemli.
     */
    private static final X509Certificate FAKE_CERT = mock(X509Certificate.class);

    // -------------------------------------------------------------------
    // Strict ID matching
    // -------------------------------------------------------------------

    @Nested
    @DisplayName("CKA_ID present → yalnızca ID ile eşleş, label fallback ASLA yapılmaz")
    class IdStrictMatching {

        @Test
        @DisplayName("Cert key rotation: PrivKey ID değişmiş ama label aynı → cert'e bağlanmamalı")
        void keyRotation_idChanged_labelSame_mustNotFallbackToLabel() throws Exception {
            // Senaryo: eski cert A (id=01) duruyor; yeni private key
            // yanlışlıkla farklı id (id=99) ile import edilmiş ama label aynı.
            // Eskisi: label fallback → Cert A'ya YANLIŞ key bağlardı.
            // Yenisi: ID match'i yok → null, key cert'e bağlanmıyor.
            List<Object> objects = new ArrayList<>();
            objects.add(newTokenObject("keypair", new byte[]{0x01}, FAKE_CERT, 0L));

            Object match = find(objects, new byte[]{0x09, 0x09}, "keypair", true);

            assertNull(match,
                "CKA_ID verilmiş ama eşleşme yok — label fallback yapmamalı; "
                + "yoksa key rotation senaryosunda yanlış key cert'e bağlanır.");
        }

        @Test
        @DisplayName("CKA_ID eşleşmesi varsa label uyumsuz olsa bile döndürülür")
        void idMatchWins_evenIfLabelDiffers() throws Exception {
            List<Object> objects = new ArrayList<>();
            Object target = newTokenObject("cert-label", new byte[]{0x01}, FAKE_CERT, 0L);
            objects.add(target);

            Object match = find(objects, new byte[]{0x01}, "completely-different-label", true);

            assertSame(target, match,
                "CKA_ID match doğru bağlama için yeterli; CKA_LABEL standartta "
                + "human-readable bir isim, eşleşme zorunlu değil.");
        }

        @Test
        @DisplayName("preferCertSide=true: cert null olan adayı atla")
        void preferCertSide_skipsKeyOnlyObjects() throws Exception {
            List<Object> objects = new ArrayList<>();
            objects.add(newTokenObject("k", new byte[]{0x01}, null /* key-only */, 42L));
            Object certObject = newTokenObject("k", new byte[]{0x01}, FAKE_CERT, 0L);
            objects.add(certObject);

            Object match = find(objects, new byte[]{0x01}, "k", true);

            assertSame(certObject, match,
                "preferCertSide=true private-key tarafından çağrıldığında, eşleşen "
                + "cert side'ı bulmalı, başka bir key entry'ye değil.");
        }
    }

    // -------------------------------------------------------------------
    // Label fallback - sadece ID yokken ve ambiguity yokken
    // -------------------------------------------------------------------

    @Nested
    @DisplayName("CKA_ID absent → label fallback sadece tek-eşleşme garantili")
    class LabelFallbackSafety {

        @Test
        @DisplayName("Duplicate label, hiçbir tarafta ID yok → ambiguous, null döner")
        void duplicateLabel_noId_returnsNull_toAvoidSilentMismatch() throws Exception {
            // Senaryo: iki cert aynı label, ID yok. Eskisi: ilk eşleşmeyi
            // rastgele dönerdi → yanlış key bağlama riski. Yenisi: ambiguous,
            // null döner — "key not found" hatası daha güvenli.
            List<Object> objects = new ArrayList<>();
            objects.add(newTokenObject("dup", null, FAKE_CERT, 0L));
            objects.add(newTokenObject("dup", null, FAKE_CERT, 0L));

            Object match = find(objects, null, "dup", true);

            assertNull(match,
                "Duplicate label + ID yok → birden fazla aday var; sessiz yanlış "
                + "eşleşme yerine null dönmeli (ambiguity).");
        }

        @Test
        @DisplayName("Tek label match, ID yok → fallback çalışır")
        void singleLabelMatch_noId_returnsCandidate() throws Exception {
            List<Object> objects = new ArrayList<>();
            Object target = newTokenObject("unique", null, FAKE_CERT, 0L);
            objects.add(target);
            objects.add(newTokenObject("other", null, FAKE_CERT, 0L));

            Object match = find(objects, null, "unique", true);

            assertSame(target, match,
                "Tek label match + her iki tarafta da ID yok → güvenli fallback.");
        }

        @Test
        @DisplayName("Label match var ama hedefin id'si dolu → fallback yapılmaz (ID-only contract)")
        void labelMatchButCandidateHasId_excluded() throws Exception {
            // Cert'in CKA_ID'si dolu olduğu için label-fallback adayı sayılmaz;
            // doğru eşleşme yolu CKA_ID üzerinden olmalı.
            List<Object> objects = new ArrayList<>();
            objects.add(newTokenObject("name", new byte[]{0x01}, FAKE_CERT, 0L));

            Object match = find(objects, null /* caller id yok */, "name", true);

            assertNull(match,
                "Cert id'li bir adayı id-vermeyen bir çağırana label ile bağlamak, "
                + "key rotation senaryolarında yanlış eşleşme açar — engellenmeli.");
        }

        @Test
        @DisplayName("Label null/empty + ID yok → null")
        void noIdNoLabel_returnsNull() throws Exception {
            List<Object> objects = new ArrayList<>();
            objects.add(newTokenObject(null, null, FAKE_CERT, 0L));

            assertNull(find(objects, null, null, true));
            assertNull(find(objects, null, "", true));
            assertNull(find(objects, new byte[0], "", true));
        }
    }

    // -------------------------------------------------------------------
    // Public API smoke: cache invalidate sonrası strict semantik korunur mu?
    // -------------------------------------------------------------------

    @Nested
    @DisplayName("Public API kontratları")
    class PublicApi {

        @Test
        @DisplayName("findByIdOrLabel package-private static — production'da değişmemeli")
        void findByIdOrLabel_signatureContract() throws Exception {
            // Bu test kontratın varlığını sabitliyor: yöntem var, parametre
            // sırası List, byte[], String, boolean. Bir refactor parametre
            // sırasını değiştirirse bu testi de güncellemek lazım — bilinçli
            // contract change işareti olsun.
            Method m = IaikPkcs11Module.class.getDeclaredMethod(
                "findByIdOrLabel", List.class, byte[].class, String.class, boolean.class);
            assertNotNull(m);
            assertEquals(java.lang.reflect.Modifier.isStatic(m.getModifiers()), true,
                "findByIdOrLabel static olmalı — instance state kullanmamalı");
        }
    }
}
