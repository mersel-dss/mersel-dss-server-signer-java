package io.mersel.dss.signer.api.services;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * X.509 sertifika uzantılarından (Key Usage, Extended Key Usage,
 * Certificate Policies) insan okunur özet bilgi üretir.
 *
 * Servis-agnostik: hem JCA {@link java.security.KeyStore} yolu (
 * {@link CertificateInfoService}) hem de raw PKCS#11 enumeration
 * ({@code Pkcs11TokenInspector}) bu helper'ı kullanır; bilgi formatı tek
 * yerde tanımlı olur ve iki kod yolu arasında tutarsızlık olmaz.
 */
public final class X509ExtensionInspector {

    private static final Logger LOGGER = LoggerFactory.getLogger(X509ExtensionInspector.class);

    // Policy Qualifier OID'leri (RFC 3280 §4.2.1.4)
    private static final String ID_QT_CPS = "1.3.6.1.5.5.7.2.1";
    private static final String ID_QT_UNOTICE = "1.3.6.1.5.5.7.2.2";

    private static final String[] KEY_USAGE_NAMES = {
        "Digital Signature",      // 0
        "Non Repudiation",        // 1
        "Key Encipherment",       // 2
        "Data Encipherment",      // 3
        "Key Agreement",          // 4
        "Key Cert Sign",          // 5
        "CRL Sign",               // 6
        "Encipher Only",          // 7
        "Decipher Only"           // 8
    };

    private X509ExtensionInspector() {
        // static-only
    }

    /**
     * X.509 KeyUsage uzantısını okunabilir, virgülle ayrılmış stringe çevirir.
     * @return Set edilmiş bit isimleri ("Digital Signature, Non Repudiation") veya
     *         uzantı yoksa / hata olursa {@code null}.
     */
    public static String extractKeyUsage(X509Certificate cert) {
        try {
            boolean[] keyUsage = cert.getKeyUsage();
            if (keyUsage == null) {
                return null;
            }

            List<String> usages = new ArrayList<String>();
            for (int i = 0; i < keyUsage.length && i < KEY_USAGE_NAMES.length; i++) {
                if (keyUsage[i]) {
                    usages.add(KEY_USAGE_NAMES[i]);
                }
            }
            return usages.isEmpty() ? null : String.join(", ", usages);
        } catch (Exception e) {
            LOGGER.debug("Key Usage bilgisi alınamadı: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Extended Key Usage uzantısındaki OID'leri olduğu gibi döndürür.
     * @return Virgülle ayrılmış OID listesi veya {@code null}.
     */
    public static String extractExtendedKeyUsage(X509Certificate cert) {
        try {
            List<String> extKeyUsage = cert.getExtendedKeyUsage();
            if (extKeyUsage == null || extKeyUsage.isEmpty()) {
                return null;
            }
            return String.join(", ", extKeyUsage);
        } catch (Exception e) {
            LOGGER.debug("Extended Key Usage bilgisi alınamadı: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Certificate Policies uzantısını parse eder; her policy için OID + opsiyonel
     * qualifier (CPS URI ya da User Notice) bilgisini birleştirir.
     *
     * @return "OID1 (qualifier1), OID2 (qualifier2)" formatında string veya {@code null}.
     */
    public static String extractCertificatePolicies(X509Certificate cert) {
        try {
            byte[] extValue = cert.getExtensionValue(Extension.certificatePolicies.getId());
            if (extValue == null) {
                return null;
            }

            ASN1Sequence sequence;
            try (ASN1InputStream outerStream = new ASN1InputStream(extValue)) {
                ASN1OctetString octets = (ASN1OctetString) outerStream.readObject();
                try (ASN1InputStream innerStream = new ASN1InputStream(octets.getOctets())) {
                    sequence = (ASN1Sequence) innerStream.readObject();
                }
            }

            CertificatePolicies policies = CertificatePolicies.getInstance(sequence);
            PolicyInformation[] policyInfos = policies.getPolicyInformation();
            if (policyInfos == null || policyInfos.length == 0) {
                return null;
            }

            List<String> policyDescriptions = new ArrayList<String>();
            for (PolicyInformation policyInfo : policyInfos) {
                ASN1ObjectIdentifier oid = policyInfo.getPolicyIdentifier();
                StringBuilder policyDesc = new StringBuilder(oid.getId());

                ASN1Sequence qualifiers = policyInfo.getPolicyQualifiers();
                if (qualifiers != null && qualifiers.size() > 0) {
                    List<String> qualifierTexts = collectPolicyQualifiers(qualifiers);
                    if (!qualifierTexts.isEmpty()) {
                        policyDesc.append(" (").append(String.join(", ", qualifierTexts)).append(")");
                    }
                }
                policyDescriptions.add(policyDesc.toString());
            }
            return policyDescriptions.isEmpty() ? null : String.join(", ", policyDescriptions);
        } catch (Exception e) {
            LOGGER.debug("Certificate Policies bilgisi alınamadı: {}", e.getMessage());
            return null;
        }
    }

    private static List<String> collectPolicyQualifiers(ASN1Sequence qualifiers) {
        List<String> qualifierTexts = new ArrayList<String>();
        for (int i = 0; i < qualifiers.size(); i++) {
            try {
                PolicyQualifierInfo qualifierInfo =
                    PolicyQualifierInfo.getInstance(qualifiers.getObjectAt(i));
                String qualifierIdStr = qualifierInfo.getPolicyQualifierId().getId();

                if (ID_QT_CPS.equals(qualifierIdStr)) {
                    ASN1String cpsUri = (ASN1String) qualifierInfo.getQualifier();
                    if (cpsUri != null) {
                        qualifierTexts.add(cpsUri.getString());
                    }
                } else if (ID_QT_UNOTICE.equals(qualifierIdStr)) {
                    ASN1Sequence userNoticeSeq = ASN1Sequence.getInstance(qualifierInfo.getQualifier());
                    if (userNoticeSeq != null && userNoticeSeq.size() > 0) {
                        for (int j = 0; j < userNoticeSeq.size(); j++) {
                            try {
                                ASN1String noticeText = (ASN1String) userNoticeSeq.getObjectAt(j);
                                if (noticeText != null) {
                                    qualifierTexts.add(noticeText.getString());
                                    break;
                                }
                            } catch (Exception ignored) {
                                // notice text tipi ASN1String değilse atla
                            }
                        }
                    }
                }
            } catch (Exception e) {
                LOGGER.debug("Policy qualifier parse edilemedi: {}", e.getMessage());
            }
        }
        return qualifierTexts;
    }
}
