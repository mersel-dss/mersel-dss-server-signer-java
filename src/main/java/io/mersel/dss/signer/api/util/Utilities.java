package io.mersel.dss.signer.api.util;

import io.mersel.dss.signer.api.util.xml.SecureXmlFactories;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class Utilities {
    private static final Logger LOGGER = LoggerFactory.getLogger(Utilities.class);

    public static Document LoadXMLFromInputStream(InputStream inputStream) throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilderFactory factory = SecureXmlFactories.newDocumentBuilderFactory();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(inputStream);
    }

    public static byte[] ZipBytes(String filename, byte[] input) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ZipOutputStream zos = new ZipOutputStream(baos);
        ZipEntry entry = new ZipEntry(filename);

        entry.setSize(input.length);
        zos.putNextEntry(entry);
        zos.write(input);
        zos.closeEntry();
        zos.close();
        return baos.toByteArray();
    }

    public static List<X509Certificate> BuildCertificateChainOnline(X509Certificate cert) throws Exception {
        List<X509Certificate> chain = new ArrayList<>();
        chain.add(cert);

        X509Certificate issuerCert;
        while ((issuerCert = fetchIssuerCertificate(cert)) != null) {
            chain.add(issuerCert);
            cert = issuerCert;

            if (cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
                LOGGER.info("✅ Root CA'ya ulaşıldı: {}", cert.getSubjectX500Principal());
                break;
            }
        }

        return chain;
    }

    private static X509Certificate fetchIssuerCertificate(X509Certificate cert) throws Exception {
        String aiaUrl = getAiaIssuerUrl(cert);
        if (aiaUrl == null) {
            throw new Exception("Issuer sertifikası için AIA URL bulunamadı!");
        }

        LOGGER.info("📥 Issuer sertifikası indiriliyor: {}", aiaUrl);
        return downloadCertificate(aiaUrl);
    }

    private static String getAiaIssuerUrl(X509Certificate cert) throws Exception {
        byte[] aiaExt = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (aiaExt == null) return null;

        ASN1Sequence seq = ASN1Sequence.getInstance(JcaX509ExtensionUtils.parseExtensionValue(aiaExt));

        for (ASN1Encodable encodable : seq.toArray()) {
            ASN1Sequence subSeq = ASN1Sequence.getInstance(encodable);
            if (subSeq.size() < 2) continue;

            ASN1ObjectIdentifier id = (ASN1ObjectIdentifier) subSeq.getObjectAt(0);
            if (id.getId().equals("1.3.6.1.5.5.7.48.2")) { // CA Issuer OID
                GeneralName generalName = GeneralName.getInstance(subSeq.getObjectAt(1));
                return ((DERIA5String) generalName.getName()).getString();
            }
        }
        return null;
    }

    private static X509Certificate downloadCertificate(String urlStr) throws Exception {
        URL url = new URL(urlStr);
        try (InputStream in = url.openStream()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(in);
        }
    }


    public static X509Certificate LoadX509Certificate(String filePath) throws Exception {
        try (InputStream in = Files.newInputStream(Paths.get(filePath))) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(in);
        }
    }


    public static void CheckIsDateValid(X509Certificate cert) {
        Date certStartTime = cert.getNotBefore();
        Date certEndTime = cert.getNotAfter();
        Date now = Calendar.getInstance().getTime();

        if (!(now.after(certStartTime) && now.before(certEndTime))) {
            throw new RuntimeException("Certificate is not valid");
        }
    }
}
