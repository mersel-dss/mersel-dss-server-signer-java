package io.mersel.dss.signer.api.services;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import io.mersel.dss.signer.api.util.xml.SecureXmlFactories;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * KamuSM XML Depo Resolver için ortak base class
 * Online ve Offline resolver'lar için ortak metodları içerir
 */
public abstract class AbstractKamuSMXmlDepoResolver implements TrustedRootCertificateResolver {

    protected static final Logger logger = LoggerFactory.getLogger(AbstractKamuSMXmlDepoResolver.class);
    
    protected final AtomicReference<List<X509Certificate>> trustedRoots = new AtomicReference<>(Collections.emptyList());
    protected final AtomicReference<List<CertificateToken>> trustedRootTokens = new AtomicReference<>(Collections.emptyList());
    
    protected CommonTrustedCertificateSource trustedCertificateSource;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * XML içeriğini yükler (subclass'lar implement eder)
     */
    protected abstract String loadRepositoryXml() throws Exception;

    /**
     * XML içeriğinden sertifikaları parse eder
     */
    protected List<X509Certificate> parseCertificates(String xmlBody) throws Exception {
        // KamuSM legacy XML formatı namespace-aware değil; SecureXmlFactories
        // namespaceAware=false varyantı ile çağrılıyor, XXE/DTD/entity vektörleri
        // yine kapalı (DOCTYPE reddedilir).
        DocumentBuilderFactory dbf = SecureXmlFactories.newDocumentBuilderFactory(false);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document document = builder.parse(new ByteArrayInputStream(xmlBody.getBytes()));

        List<String> values = new ArrayList<String>();

        // KamuSM XML formati: Her <koksertifika> altinda <mValue> tag'i var
        NodeList kokNodes = document.getElementsByTagName("koksertifika");
        for (int i = 0; i < kokNodes.getLength(); i++) {
            Element kokElement = (Element) kokNodes.item(i);
            
            // Sadece <mValue> tag'ini al
            NodeList mValueNodes = kokElement.getElementsByTagName("mValue");
            if (mValueNodes.getLength() > 0) {
                String certBase64 = mValueNodes.item(0).getTextContent();
                values.add(certBase64);
            } else {
                logger.warn("koksertifika #{} icin mValue bulunamadi, atlanıyor", i + 1);
            }
        }

        List<X509Certificate> certificates = new ArrayList<X509Certificate>();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        
        for (int i = 0; i < values.size(); i++) {
            String base64 = values.get(i);
            if (base64 == null || base64.isEmpty()) {
                continue;
            }
            
            // Base64 76 kolon formatinda olabilir (satir sonlari, bosluklar var)
            // Tum whitespace karakterlerini temizle
            String normalized = base64.replaceAll("\\s+", "");
            if (normalized.isEmpty()) {
                continue;
            }
            
            try {
                // Base64.getMimeDecoder() 76 kolon formatini otomatik handle eder
                byte[] der = Base64.getMimeDecoder().decode(normalized);
                X509Certificate certificate = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(der));
                certificates.add(certificate);
                logger.debug("Kok sertifika #{} basariyla parse edildi", i + 1);
            } catch (Exception e) {
                logger.warn("Kok sertifika #{} parse edilemedi, atlaniyor: {}", i + 1, e.getMessage());
            }
        }
        
        logger.info("Toplam {} adet kok sertifika parse edildi", certificates.size());
        return certificates;
    }

    /**
     * Trusted certificate source'u gunceller
     */
    protected void updateTrustedCertificateSource() {
        if (trustedCertificateSource == null) {
            trustedCertificateSource = new CommonTrustedCertificateSource();
        }
        
        // KamuSM sertifikalarini ekle
        for (CertificateToken token : trustedRootTokens.get()) {
            trustedCertificateSource.addCertificate(token);
        }
        
        logger.info("Trusted certificate source updated with {} certificates", 
            trustedCertificateSource.getCertificates().size());
    }

    @Override
    public List<X509Certificate> getTrustedRoots() {
        return trustedRoots.get();
    }

    @Override
    public List<CertificateToken> getTrustedRootTokens() {
        return trustedRootTokens.get();
    }

    @Override
    public CommonTrustedCertificateSource getTrustedCertificateSource() {
        if (trustedCertificateSource == null) {
            updateTrustedCertificateSource();
        }
        return trustedCertificateSource;
    }

    @Override
    public void addTrustedCertificate(CertificateToken certificate) {
        if (trustedCertificateSource == null) {
            trustedCertificateSource = new CommonTrustedCertificateSource();
        }
        trustedCertificateSource.addCertificate(certificate);
        logger.info("Added trusted certificate: {}", certificate.getSubject());
    }

    @Override
    public void addTrustedCertificate(X509Certificate certificate) {
        addTrustedCertificate(new CertificateToken(certificate));
    }

    @Override
    public boolean isTrusted(CertificateToken certificate) {
        if (trustedCertificateSource == null) {
            return false;
        }
        return trustedCertificateSource.getCertificates().contains(certificate);
    }
}

