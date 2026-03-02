package io.mersel.dss.signer.api.services.signature.cades;

import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.util.CryptoUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.concurrent.Semaphore;

/**
 * CAdES-BES seviyesinde elektronik imza üreten servis.
 *
 * <p>BouncyCastle CMS altyapısı üzerinden RFC 5652 (CMS) ve ETSI TS 101 733 (CAdES)
 * gereksinimlerine uygun imzalar oluşturur. Her imzada {@code SigningCertificateV2}
 * signed attribute'ü eklenerek CAdES-BES uyumu sağlanır; bu attribute imzacının
 * sertifikasının hash'ini taşır ve sertifika ikame saldırılarını önler.</p>
 *
 * <p>İmzalama sırasında sertifikanın {@code sigAlgName} bilgisinden hash algoritması
 * (SHA-256, SHA-384, SHA-512) dinamik olarak çözümlenir. Böylece farklı CA'lardan
 * gelen sertifikalar için ayrı konfigürasyon gerekmez.</p>
 *
 * <h3>Eşzamanlılık</h3>
 * <p>PKCS#11 (HSM) session havuzlarının tükenmesini engellemek için eş zamanlı imza
 * sayısı bir {@link Semaphore} ile sınırlandırılır. Semaphore kapasitesi dışarıdan
 * (genellikle Spring konfigürasyonundan) belirlenir.</p>
 *
 * <h3>Bilinen Sorunlar</h3>
 * <p>JDK 8 + SunPKCS11 ortamında explicit-form EC parametreleri kullanan anahtarlarda
 * {@code P11Key.keyLength} alanı hatalı hesaplanabiliyor. Bu durum
 * {@link #fixP11KeyLengthIfNeeded(PrivateKey, X509Certificate)} ile reflection
 * üzerinden düzeltilir. Detaylar ilgili metodun Javadoc'unda açıklanmıştır.</p>
 *
 * @see CryptoUtils#getSignatureAlgorithm(PrivateKey, X509Certificate)
 */
@Service
public class CAdESSignatureService {

    private static final Logger LOGGER = LoggerFactory.getLogger(CAdESSignatureService.class);

    private final Semaphore semaphore;

    /**
     * @param signatureSemaphore Eş zamanlı imza işlemi sayısını kısıtlayan semaphore.
     *                           HSM session limiti veya CPU yoğunluğuna göre ayarlanır.
     */
    public CAdESSignatureService(Semaphore signatureSemaphore) {
        this.semaphore = signatureSemaphore;
    }

    /**
     * Verilen stream'deki veriyi okuyarak CAdES-BES imzası üretir.
     *
     * <p>Stream tamamıyla belleğe okunur, ardından {@link #createCAdESSignature} ile
     * imzalanır. Büyük dosyalarda bellek tüketimine dikkat edilmelidir; gerekirse
     * uygulama tarafında dosya boyutu kontrolü yapılmalıdır.</p>
     *
     * @param dataInputStream imzalanacak dosyanın stream'i — metot içinde tüketilir, kapatılmaz
     * @param detached        {@code true} → ayrık imza (orijinal veri CMS zarfına gömülmez),
     *                        {@code false} → gömülü imza (orijinal veri zarfın içinde)
     * @param material        sertifika zinciri ve private key'i barındıran imzalama materyali
     * @return imzalanmış byte dizisi ve Base64 kodlanmış imza değerini içeren {@link SignResponse}
     * @throws SignatureException imza oluşturma sırasında herhangi bir hata meydana gelirse
     */
    public SignResponse signData(InputStream dataInputStream,
                                 boolean detached,
                                 SigningMaterial material) {
        try {
            byte[] contentBytes = IOUtils.toByteArray(dataInputStream);
            byte[] signatureBytes = createCAdESSignature(contentBytes, detached, material);

            String encodedSignature = Base64.getEncoder().encodeToString(signatureBytes);
            LOGGER.info("CAdES imzası başarıyla oluşturuldu (detached: {})", detached);

            return new SignResponse(signatureBytes, encodedSignature);

        } catch (SignatureException e) {
            throw e;
        } catch (Exception e) {
            LOGGER.error("CAdES imzası oluşturulurken hata", e);
            throw new SignatureException("CAdES imzası oluşturulamadı", e);
        }
    }

    /**
     * CAdES-BES yapısını oluşturan ana metot.
     *
     * <p>İşlem adımları:</p>
     * <ol>
     *   <li>Sertifikanın imza algoritmasından digest algoritması çözümlenir (SHA-256/384/512)</li>
     *   <li>Sertifikanın DER kodlaması hash'lenerek {@link ESSCertIDv2} oluşturulur</li>
     *   <li>{@code SigningCertificateV2} attribute'ü signed attributes'a eklenir</li>
     *   <li>{@link #buildContentSigner} ile JCA tabanlı ContentSigner hazırlanır</li>
     *   <li>BouncyCastle {@link CMSSignedDataGenerator} üzerinden CMS zarfı üretilir</li>
     * </ol>
     *
     * <p>Semaphore acquire/release CMS generate aşamasını sarar; böylece HSM'e yapılan
     * eş zamanlı çağrı sayısı kontrol altında tutulur.</p>
     *
     * @param contentBytes imzalanacak ham veri
     * @param detached     ayrık mı gömülü mü imza üretileceği
     * @param material     sertifika ve anahtar bilgileri
     * @return DER kodlanmış CMS SignedData byte dizisi
     */
    private byte[] createCAdESSignature(byte[] contentBytes,
                                        boolean detached,
                                        SigningMaterial material) throws Exception {
        // Sertifikanın sigAlgName alanından digest algoritmasını belirle.
        // Örneğin SHA384withRSA → SHA-384, SHA256withECDSA → SHA-256
        String digestAlgName = resolveDigestAlgorithmName(material);
        ASN1ObjectIdentifier digestOid = resolveDigestOid(digestAlgName);

        // CAdES-BES zorunluluğu: imzacı sertifikasının hash'i imza içine gömülmeli.
        // Bu hash sayesinde doğrulayıcı, imzanın hangi sertifikayla atıldığını kesin
        // olarak belirler ve farklı sertifika ikame edilemez.
        MessageDigest messageDigest = MessageDigest.getInstance(digestAlgName);
        byte[] certificateHash = messageDigest.digest(
                material.getSigningCertificate().getEncoded());

        // IssuerSerial: sertifikayı benzersiz tanımlayan (issuer DN + serial number) çifti
        GeneralName generalName = new GeneralName(
                X500Name.getInstance(material.getSigningCertificate()
                        .getIssuerX500Principal().getEncoded()));
        GeneralNames generalNames = new GeneralNames(generalName);
        IssuerSerial issuerSerial = new IssuerSerial(
                generalNames, material.getSigningCertificate().getSerialNumber());

        // ESSCertIDv2: hash + algoritma + issuerSerial üçlüsünü tek yapıda birleştirir
        ESSCertIDv2 essCert = new ESSCertIDv2(
                new AlgorithmIdentifier(digestOid),
                certificateHash, issuerSerial);
        SigningCertificateV2 signingCertificateV2 = new SigningCertificateV2(
                new ESSCertIDv2[]{essCert});
        Attribute signingCertAttr = new Attribute(
                PKCSObjectIdentifiers.id_aa_signingCertificateV2,
                new DERSet(signingCertificateV2));

        // Signed attributes: imzanın parçası olarak hash'lenen ve imzalanan attribute'ler.
        // content-type, message-digest gibi zorunlu alanlar BouncyCastle tarafından
        // otomatik eklenir; biz sadece SigningCertificateV2'yi ekliyoruz.
        ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
        signedAttributes.add(signingCertAttr);
        AttributeTable attributeTable = new AttributeTable(signedAttributes);

        JcaSignerInfoGeneratorBuilder signerInfoGeneratorBuilder =
                new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().build())
                        .setSignedAttributeGenerator(
                                new DefaultSignedAttributeTableGenerator(attributeTable));

        // İmza algoritması sertifikanın public key tipine göre belirlenir.
        // CryptoUtils, key tipi ile sertifika sigAlgName arasında uyumsuzluk
        // olduğunda (örneğin RSA key + ECDSA sigAlg) key tipini baz alır.
        String signatureAlgorithm = CryptoUtils.getSignatureAlgorithm(
                material.getPrivateKey(), material.getSigningCertificate());
        ContentSigner contentSigner = buildContentSigner(
                signatureAlgorithm, material.getPrivateKey(), material.getSigningCertificate());

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(
                signerInfoGeneratorBuilder.build(contentSigner,
                        material.getSigningCertificate()));
        // Sertifika zincirinin tamamı CMS yapısına eklenir; doğrulayıcı taraf
        // ara sertifikalara ayrıca ihtiyaç duymadan zinciri kurabilir.
        generator.addCertificates(new JcaCertStore(material.getCertificateChain()));

        semaphore.acquire();
        try {
            // CMSSignedDataGenerator.generate ikinci parametresi encapsulate:
            //   true  → veri CMS zarfının içine gömülür (attached)
            //   false → yalnızca imza üretilir, veri dışarıda kalır (detached)
            CMSSignedData signedData = generator.generate(
                    new CMSProcessableByteArray(contentBytes), !detached);
            return signedData.getEncoded();
        } finally {
            semaphore.release();
        }
    }

    /**
     * JCA {@link Signature} API'sini saran bir BouncyCastle {@link ContentSigner} üretir.
     *
     * <p>BouncyCastle'ın kendi {@code JcaContentSignerBuilder}'ı yerine elle ContentSigner
     * oluşturmamızın sebebi PKCS#11 provider'ını ve key düzeltmesini kontrol etmek.
     * Özellikle HSM üzerindeki anahtarlarda SunPKCS11 provider'ının açıkça belirtilmesi
     * gerekiyor; aksi halde JCA varsayılan provider sırasına göre yazılım tabanlı bir
     * provider seçebilir ve HSM'deki private key'e erişemez.</p>
     *
     * <p>Ayrıca JDK 8'deki {@code P11Key.keyLength} hatası yüzünden imzalama öncesinde
     * {@link #fixP11KeyLengthIfNeeded} çağrılarak EC anahtarlarındaki bit uzunluğu
     * düzeltilir. Bu düzeltme yapılmazsa SunPKCS11'in iç doğrulaması
     * {@code InvalidKeyException} fırlatır.</p>
     *
     * @param algorithm  JCA algoritma adı (örn. "SHA256withRSA", "SHA384withECDSA")
     * @param privateKey imzalama için kullanılacak private key
     * @param cert       key düzeltmesi için referans sertifika
     * @return yapılandırılmış ContentSigner nesnesi
     */
    private static ContentSigner buildContentSigner(String algorithm,
                                                    PrivateKey privateKey,
                                                    X509Certificate cert)
            throws java.security.NoSuchAlgorithmException, java.security.InvalidKeyException {
        fixP11KeyLengthIfNeeded(privateKey, cert);
        Provider pkcs11 = resolvePkcs11Provider(privateKey);
        final Signature jcaSig = (pkcs11 != null)
                ? Signature.getInstance(algorithm, pkcs11)
                : Signature.getInstance(algorithm);
        jcaSig.initSign(privateKey);
        final AlgorithmIdentifier sigAlgId =
                new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
        return new ContentSigner() {
            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier() { return sigAlgId; }

            @Override
            public OutputStream getOutputStream() {
                return new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        try { jcaSig.update((byte) b); }
                        catch (java.security.SignatureException e) { throw new IOException(e); }
                    }
                    @Override
                    public void write(byte[] b, int off, int len) throws IOException {
                        try { jcaSig.update(b, off, len); }
                        catch (java.security.SignatureException e) { throw new IOException(e); }
                    }
                };
            }

            @Override
            public byte[] getSignature() {
                try { return jcaSig.sign(); }
                catch (java.security.SignatureException e) { throw new RuntimeException(e); }
            }
        };
    }

    /**
     * Private key'in PKCS#11 (HSM) kaynaklı olup olmadığını kontrol eder.
     *
     * <p>Sınıf adında "P11Key" veya "pkcs11" geçiyorsa kurulu SunPKCS11 provider'ını
     * döndürür. Yazılım tabanlı anahtarlarda (PKCS#12, JKS vb.) {@code null} döner
     * ve JCA varsayılan provider seçimini kullanır.</p>
     *
     * @param privateKey kontrol edilecek private key
     * @return SunPKCS11 provider'ı veya yazılım anahtarları için {@code null}
     */
    private static Provider resolvePkcs11Provider(PrivateKey privateKey) {
        String className = privateKey.getClass().getName();
        if (className.contains("P11Key") || className.contains("pkcs11")) {
            for (Provider p : Security.getProviders()) {
                if (p.getName().startsWith("SunPKCS11")) {
                    return p;
                }
            }
        }
        return null;
    }

    /**
     * JDK 8 + SunPKCS11 ortamında EC anahtarlarının {@code keyLength} alanını düzeltir.
     *
     * <p><b>Sorunun kökeni:</b> SunEC provider'ı kaldırıldığında veya explicit-form EC
     * parametreleri kullanıldığında, SunPKCS11 eğri bit uzunluğunu DER encoding'in bayt
     * uzunluğundan hesaplamaya çalışır. Örneğin P-256 eğrisi için 256 bit yerine
     * DER bayt sayısı × 8 gibi anlamsız bir değer ortaya çıkar. Bu değer SunPKCS11'in
     * iç {@code checkKeySize} kontrolünde reddedilir.</p>
     *
     * <p><b>Çözüm:</b> Sertifikanın SubjectPublicKeyInfo alanından gerçek eğri bit
     * uzunluğu okunur ve reflection ile {@code P11Key.keyLength} alanı düzeltilir.
     * Bu workaround yalnızca JDK 8 ortamında gereklidir; JDK 11+ bu hesaplamayı
     * doğru yapar.</p>
     *
     * @param privateKey düzeltilecek private key (P11Key değilse hiçbir şey yapılmaz)
     * @param cert       doğru eğri boyutunu belirlemek için referans sertifika
     */
    private static void fixP11KeyLengthIfNeeded(PrivateKey privateKey, X509Certificate cert) {
        try {
            if (!privateKey.getClass().getName().contains("P11Key")) return;
            String algo = privateKey.getAlgorithm();
            if (!"EC".equalsIgnoreCase(algo) && !"ECDSA".equalsIgnoreCase(algo)) return;

            int correctBits = getECKeySizeFromCertificate(cert);
            if (correctBits <= 0 || correctBits > 640) return;

            Class<?> clazz = privateKey.getClass();
            Field keyLengthField = null;
            while (clazz != null) {
                try {
                    keyLengthField = clazz.getDeclaredField("keyLength");
                    break;
                } catch (NoSuchFieldException e) {
                    clazz = clazz.getSuperclass();
                }
            }
            if (keyLengthField == null) return;

            keyLengthField.setAccessible(true);
            int current = (int) keyLengthField.get(privateKey);
            if (current != correctBits) {
                LOGGER.warn("P11Key.keyLength düzeltiliyor: {} -> {} bit (JDK8 explicit EC params bug)",
                        current, correctBits);
                keyLengthField.set(privateKey, correctBits);
            }
        } catch (Exception e) {
            LOGGER.debug("P11Key.keyLength düzeltme atlandı: {}", e.getMessage());
        }
    }

    /**
     * Sertifikanın public key bilgisinden EC eğrisinin bit uzunluğunu çıkarır.
     *
     * <p>Hem named-curve (OID ile tanımlı, örn. secp256r1) hem de explicit-form
     * (eğri parametreleri açıkça belirtilmiş) EC parametrelerini destekler.
     * Named-curve durumunda BouncyCastle'ın {@code ECNamedCurveTable} ve
     * {@code CustomNamedCurves} tablolarına bakılır.</p>
     *
     * @param cert eğri bilgisi okunacak X.509 sertifikası
     * @return eğri bit uzunluğu (örn. 256, 384, 521) veya belirlenemezse 0
     */
    private static int getECKeySizeFromCertificate(X509Certificate cert) {
        try {
            if (cert == null) return 0;
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki =
                    org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(
                            cert.getPublicKey().getEncoded());
            if (spki.getAlgorithm().getParameters() == null) return 0;
            org.bouncycastle.asn1.ASN1Primitive params =
                    spki.getAlgorithm().getParameters().toASN1Primitive();
            if (params instanceof ASN1ObjectIdentifier) {
                org.bouncycastle.asn1.x9.X9ECParameters x9 =
                        org.bouncycastle.asn1.x9.ECNamedCurveTable.getByOID(
                                (ASN1ObjectIdentifier) params);
                if (x9 == null) {
                    x9 = org.bouncycastle.crypto.ec.CustomNamedCurves.getByOID(
                            (ASN1ObjectIdentifier) params);
                }
                if (x9 != null) return x9.getCurve().getFieldSize();
            } else {
                org.bouncycastle.asn1.x9.X9ECParameters x9 =
                        org.bouncycastle.asn1.x9.X9ECParameters.getInstance(params);
                if (x9 != null) return x9.getCurve().getFieldSize();
            }
        } catch (Exception e) {
            LOGGER.debug("EC key boyutu sertifikadan alınamadı: {}", e.getMessage());
        }
        return 0;
    }

    /**
     * Sertifikanın imza algoritmasından digest (hash) algoritma adını çözümler.
     *
     * <p>Sertifikanın {@code getSigAlgName()} değerindeki SHA varyantı aranır.
     * Bulunamazsa güvenli varsayılan olarak SHA-256 döner. Bu değer hem
     * {@code SigningCertificateV2} hash'i hem de CMS digest hesaplaması için kullanılır.</p>
     *
     * @param material imzalama materyali (sertifika bilgisi için)
     * @return JCA uyumlu digest algoritma adı (örn. "SHA-256", "SHA-384", "SHA-512")
     */
    private String resolveDigestAlgorithmName(SigningMaterial material) {
        String sigAlg = material.getSigningCertificate().getSigAlgName();
        if (sigAlg != null) {
            String upper = sigAlg.toUpperCase(java.util.Locale.ROOT);
            if (upper.contains("SHA384")) return "SHA-384";
            if (upper.contains("SHA512")) return "SHA-512";
            if (upper.contains("SHA224")) return "SHA-224";
        }
        return "SHA-256";
    }

    /**
     * Digest algoritma adını karşılık gelen NIST OID'sine çevirir.
     *
     * @param digestAlgName JCA formatında digest adı (örn. "SHA-384")
     * @return ilgili {@link NISTObjectIdentifiers} OID'si
     */
    private ASN1ObjectIdentifier resolveDigestOid(String digestAlgName) {
        switch (digestAlgName) {
            case "SHA-384": return NISTObjectIdentifiers.id_sha384;
            case "SHA-512": return NISTObjectIdentifiers.id_sha512;
            case "SHA-224": return NISTObjectIdentifiers.id_sha224;
            default:        return NISTObjectIdentifiers.id_sha256;
        }
    }
}