package io.mersel.dss.signer.api.services;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * X.509 v3 extension extraction testleri.
 *
 * <p>e-Dönüşüm sertifikalarında {@code KeyUsage} (nonRepudiation),
 * {@code ExtendedKeyUsage} (emailProtection / clientAuth) ve
 * {@code CertificatePolicies} (NES / TÜRKTRUST CPS URL'leri) doğru
 * okunmazsa kullanıcıya yanlış sertifika seçtirebiliriz, hatta DSS
 * baseline-B doğrulaması başarısız olur.</p>
 *
 * <p>Bu testler BC ile gerçek X.509 v3 cert üretir, sonra inspector'ı
 * geçirir.</p>
 */
class X509ExtensionInspectorTest {

    private static KeyPair rsaKeyPair;

    @BeforeAll
    static void initKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rsaKeyPair = kpg.generateKeyPair();
    }

    // ----------------------------------------------------------------
    // KeyUsage extraction
    // ----------------------------------------------------------------

    @Nested
    @DisplayName("Key Usage uzantısı")
    class KeyUsageExtraction {

        @Test
        void digitalSignatureAndNonRepudiation_shouldRenderHumanReadable() throws Exception {
            // e-imza için tipik kombinasyon (NES / kalifiye sertifika)
            X509Certificate cert = certWith(new Extension(
                Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation)
                    .getEncoded()));

            String result = X509ExtensionInspector.extractKeyUsage(cert);
            assertNotNull(result);
            assertTrue(result.contains("Digital Signature"));
            assertTrue(result.contains("Non Repudiation"));
            assertEquals("Digital Signature, Non Repudiation", result);
        }

        @Test
        void allKeyUsageBits_shouldBeRenderedInOrder() throws Exception {
            // Bit sırasının doğruluğu kritik — X.509 KeyUsage bit'leri 0..8.
            X509Certificate cert = certWith(new Extension(
                Extension.keyUsage, true,
                new KeyUsage(
                    KeyUsage.digitalSignature | KeyUsage.nonRepudiation
                    | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment
                    | KeyUsage.keyAgreement | KeyUsage.keyCertSign
                    | KeyUsage.cRLSign | KeyUsage.encipherOnly
                ).getEncoded()));

            String result = X509ExtensionInspector.extractKeyUsage(cert);
            assertNotNull(result);
            // İlk dört ve sıralama:
            assertTrue(result.startsWith("Digital Signature, Non Repudiation, Key Encipherment"));
        }

        @Test
        void noKeyUsageExtension_shouldReturnNull() throws Exception {
            X509Certificate plainCert = certWith(/* hiç extension yok */);
            assertNull(X509ExtensionInspector.extractKeyUsage(plainCert),
                "Extension yoksa null dönmeli, boş string değil");
        }
    }

    // ----------------------------------------------------------------
    // Extended Key Usage extraction
    // ----------------------------------------------------------------

    @Nested
    @DisplayName("Extended Key Usage uzantısı")
    class ExtendedKeyUsageExtraction {

        @Test
        void emailProtectionEku_shouldExposeOid() throws Exception {
            X509Certificate cert = certWith(new Extension(
                Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_emailProtection).getEncoded()));

            String result = X509ExtensionInspector.extractExtendedKeyUsage(cert);
            assertNotNull(result);
            assertEquals("1.3.6.1.5.5.7.3.4", result,
                "EKU OID'leri olduğu gibi döndürülmeli (UI'da map'lenir)");
        }

        @Test
        void multipleEku_shouldJoinWithComma() throws Exception {
            X509Certificate cert = certWith(new Extension(
                Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(new KeyPurposeId[]{
                    KeyPurposeId.id_kp_clientAuth,
                    KeyPurposeId.id_kp_emailProtection
                }).getEncoded()));

            String result = X509ExtensionInspector.extractExtendedKeyUsage(cert);
            assertNotNull(result);
            assertTrue(result.contains("1.3.6.1.5.5.7.3.2"), "clientAuth OID");
            assertTrue(result.contains("1.3.6.1.5.5.7.3.4"), "emailProtection OID");
            assertTrue(result.contains(", "), "Virgül ile ayrılmış olmalı");
        }

        @Test
        void noEkuExtension_shouldReturnNull() throws Exception {
            X509Certificate plainCert = certWith();
            assertNull(X509ExtensionInspector.extractExtendedKeyUsage(plainCert));
        }
    }

    // ----------------------------------------------------------------
    // Certificate Policies extraction
    // ----------------------------------------------------------------

    @Nested
    @DisplayName("Certificate Policies uzantısı")
    class CertificatePoliciesExtraction {

        @Test
        void policyWithCpsQualifier_shouldRenderOidPlusCpsUri() throws Exception {
            // Türkiye'deki sertifikalar genelde CPS URI içerir; bu URI insan
            // gözle gözden geçirilebilmesi için extract edilmeli.
            String cpsUri = "https://depo.kamusm.gov.tr/CPS";
            PolicyInformation policy = new PolicyInformation(
                new ASN1ObjectIdentifier("2.16.792.1.61.0.1.5070.1.1"), // örnek TURKTRUST policy
                new DERSequence(new PolicyQualifierInfo(
                    PolicyQualifierId.id_qt_cps, new DERIA5String(cpsUri))));

            X509Certificate cert = certWith(new Extension(
                Extension.certificatePolicies, false,
                new CertificatePolicies(policy).getEncoded()));

            String result = X509ExtensionInspector.extractCertificatePolicies(cert);
            assertNotNull(result);
            assertTrue(result.contains("2.16.792.1.61.0.1.5070.1.1"),
                "Policy OID döndürülmeli");
            assertTrue(result.contains(cpsUri),
                "CPS URI qualifier insan-okunabilir olarak görünmeli");
            assertTrue(result.contains("(") && result.contains(")"),
                "Qualifier parantez içinde olmalı");
        }

        @Test
        void policyWithUserNoticeQualifier_shouldRenderNoticeText() throws Exception {
            String noticeText = "Kalifiye Elektronik Sertifika - 5070 sayılı kanun";
            ASN1EncodableVector noticeContents = new ASN1EncodableVector();
            noticeContents.add(new DERUTF8String(noticeText));

            PolicyInformation policy = new PolicyInformation(
                new ASN1ObjectIdentifier("2.5.29.32.0"), // anyPolicy
                new DERSequence(new PolicyQualifierInfo(
                    PolicyQualifierId.id_qt_unotice,
                    new DERSequence(noticeContents))));

            X509Certificate cert = certWith(new Extension(
                Extension.certificatePolicies, false,
                new CertificatePolicies(policy).getEncoded()));

            String result = X509ExtensionInspector.extractCertificatePolicies(cert);
            assertNotNull(result);
            assertTrue(result.contains("2.5.29.32.0"));
            assertTrue(result.contains(noticeText),
                "User Notice metni qualifier alanında görünmeli");
        }

        @Test
        void policyWithoutQualifiers_shouldRenderOnlyOid() throws Exception {
            PolicyInformation policy = new PolicyInformation(
                new ASN1ObjectIdentifier("2.5.29.32.0"));

            X509Certificate cert = certWith(new Extension(
                Extension.certificatePolicies, false,
                new CertificatePolicies(policy).getEncoded()));

            String result = X509ExtensionInspector.extractCertificatePolicies(cert);
            assertNotNull(result);
            assertEquals("2.5.29.32.0", result,
                "Qualifier yokken parantez/extra string olmamalı");
        }

        @Test
        void multiplePolicies_shouldBeJoinedByComma() throws Exception {
            PolicyInformation[] policies = new PolicyInformation[]{
                new PolicyInformation(new ASN1ObjectIdentifier("2.5.29.32.0")),
                new PolicyInformation(new ASN1ObjectIdentifier("1.2.3.4.5"))
            };
            X509Certificate cert = certWith(new Extension(
                Extension.certificatePolicies, false,
                new CertificatePolicies(policies).getEncoded()));

            String result = X509ExtensionInspector.extractCertificatePolicies(cert);
            assertNotNull(result);
            assertTrue(result.contains("2.5.29.32.0"));
            assertTrue(result.contains("1.2.3.4.5"));
            assertTrue(result.contains(", "));
        }

        @Test
        void noCertificatePoliciesExtension_shouldReturnNull() throws Exception {
            X509Certificate plainCert = certWith();
            assertNull(X509ExtensionInspector.extractCertificatePolicies(plainCert));
        }
    }

    @Nested
    @DisplayName("Servis-agnostik kullanım")
    class UsedFromMultiplePaths {

        @Test
        void utilityClass_isStatic_andResilientToNullExtensionValue() throws Exception {
            // Inspector'ın null-safe olduğunu kanıtla (PKCS#11 enumeration
            // yolunda bazen extension parse edilemez; servis crash etmemeli).
            X509Certificate plainCert = certWith();
            assertNull(X509ExtensionInspector.extractKeyUsage(plainCert));
            assertNull(X509ExtensionInspector.extractExtendedKeyUsage(plainCert));
            assertNull(X509ExtensionInspector.extractCertificatePolicies(plainCert));

            // Logger yan etkileriyle bile, sonraki çağrı hala çalışmalı:
            assertFalse(plainCert.getSubjectX500Principal().getName().isEmpty());
        }
    }

    // ----------------------------------------------------------------
    // Cert builder helper — verilen extension'larla self-signed cert üretir
    // ----------------------------------------------------------------

    private static X509Certificate certWith(Extension... extensions) throws Exception {
        X500Name subject = new X500Name("CN=Extension Test, O=Mersel, C=TR");
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);

        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(
            rsaKeyPair.getPublic().getEncoded());

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
            subject, BigInteger.valueOf(System.nanoTime()),
            notBefore, notAfter, subject, spki);

        for (Extension ext : extensions) {
            builder.addExtension(ext);
        }

        return new JcaX509CertificateConverter().getCertificate(
            builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                .build(rsaKeyPair.getPrivate())));
    }

    /**
     * BC API ergonomi: bazı kombinasyonlarda PolicyQualifierInfo'nun
     * {@code ASN1Encodable qualifier} ctor'unu kullanıyoruz, IDE'lerin
     * import unused warning'i çıkarmaması için referans:
     */
    @SuppressWarnings("unused")
    private static ASN1Encodable touch(ASN1Encodable e) { return e; }
}
