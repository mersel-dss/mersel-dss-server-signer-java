package io.mersel.dss.signer.api.services.signature.xades;

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.identifier.EntityIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSourceEntity;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.SignerIdentifier;

import java.security.PublicKey;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * İstek bazında <em>thread-izole</em> bir DSS adjunct sertifika kaynağı.
 *
 * <h3>Neden var?</h3>
 * <p>{@code CommonCertificateVerifier} uygulamada <strong>singleton</strong>
 * olarak paylaşılır (bkz. {@code SignatureConfiguration#certificateVerifier()})
 * ve {@code XAdESService} / {@code XAdESLevelUpgradeService} / CAdES servisi
 * gibi tüm imza yollarınca ortak kullanılır. Önceki tasarımda her XAdES isteği,
 * imzalama sertifika zincirini bu paylaşılan verifier'ın <em>adjunct</em>
 * kaynağına yazıyordu. {@code signatureSemaphore} permits &gt; 1 olduğundan
 * (eş zamanlı imza), iki istek aynı anda adjunct'ı set/okuyabiliyordu:</p>
 *
 * <ul>
 *   <li>İstek A kendi zincirini set eder.</li>
 *   <li>İstek B araya girip adjunct'ı kendi zinciriyle değiştirir.</li>
 *   <li>A'nın DSS çağrısı (özellikle -LT/-LTA seviye yükseltmesinde zincir
 *       oluştururken) <strong>B'nin</strong> kaynağını okur → A'nın ara
 *       sertifikaları bulunamaz; eksik zincir / hata.</li>
 * </ul>
 *
 * <h3>Çözüm</h3>
 * <p>Bu kaynak, tüm sorgu/ekleme işlemlerini {@link ThreadLocal} ile sarmalanmış
 * bir {@link CommonCertificateSource}'a delege eder. Böylece her istek
 * (request thread) yalnızca <em>kendi</em> sertifikalarını görür; eş zamanlı
 * istekler birbirini ezmez. {@link #resetForCurrentThread()} istek bitiminde
 * çağrılarak thread-pool yeniden kullanımında artık sertifika kalmasını
 * (bellek tutulması / başka isteğe sızma) önler.</p>
 *
 * <p>Yalnızca DSS'in herkese açık {@link CertificateSource} API'si üzerinden
 * çalışır; kara-kutu DSS iç durumuna dokunmaz.</p>
 */
public final class ThreadLocalAdjunctCertificateSource extends CommonCertificateSource {

    private final ThreadLocal<CommonCertificateSource> delegate =
            ThreadLocal.withInitial(CommonCertificateSource::new);

    private CommonCertificateSource current() {
        return delegate.get();
    }

    /**
     * Geçerli thread'e bağlı sertifikaları temizler. İstek bitiminde
     * (finally) çağrılmalıdır.
     */
    public void resetForCurrentThread() {
        delegate.remove();
    }

    @Override
    public CertificateToken addCertificate(CertificateToken certificate) {
        return current().addCertificate(certificate);
    }

    @Override
    public boolean isKnown(CertificateToken token) {
        return current().isKnown(token);
    }

    @Override
    public List<CertificateToken> getCertificates() {
        return current().getCertificates();
    }

    @Override
    public List<CertificateSourceEntity> getEntities() {
        return current().getEntities();
    }

    @Override
    public Set<CertificateToken> getByPublicKey(PublicKey publicKey) {
        return current().getByPublicKey(publicKey);
    }

    @Override
    public Set<CertificateToken> getByEntityKey(EntityIdentifier entityKey) {
        return current().getByEntityKey(entityKey);
    }

    @Override
    public Set<CertificateToken> getBySki(byte[] ski) {
        return current().getBySki(ski);
    }

    @Override
    public Set<CertificateToken> getBySubject(X500PrincipalHelper subject) {
        return current().getBySubject(subject);
    }

    @Override
    public Set<CertificateToken> getBySignerIdentifier(SignerIdentifier signerIdentifier) {
        return current().getBySignerIdentifier(signerIdentifier);
    }

    @Override
    public Set<CertificateToken> getByCertificateDigest(Digest digest) {
        return current().getByCertificateDigest(digest);
    }

    @Override
    public Set<CertificateToken> findTokensFromCertRef(CertificateRef certificateRef) {
        return current().findTokensFromCertRef(certificateRef);
    }

    @Override
    public int getNumberOfCertificates() {
        return current().getNumberOfCertificates();
    }

    @Override
    public int getNumberOfEntities() {
        return current().getNumberOfEntities();
    }

    @Override
    public CertificateSourceType getCertificateSourceType() {
        return current().getCertificateSourceType();
    }

    @Override
    public boolean isTrusted(CertificateToken certificateToken) {
        return current().isTrusted(certificateToken);
    }

    @Override
    public boolean isTrustedAtTime(CertificateToken certificateToken, Date date) {
        return current().isTrustedAtTime(certificateToken, date);
    }

    @Override
    public boolean isAllSelfSigned() {
        return current().isAllSelfSigned();
    }

    @Override
    public boolean isCertificateSourceEqual(CertificateSource certificateSource) {
        return current().isCertificateSourceEqual(certificateSource);
    }

    @Override
    public boolean isCertificateSourceEquivalent(CertificateSource certificateSource) {
        return current().isCertificateSourceEquivalent(certificateSource);
    }
}
