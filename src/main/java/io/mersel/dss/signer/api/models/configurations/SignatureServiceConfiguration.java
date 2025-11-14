package io.mersel.dss.signer.api.models.configurations;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class SignatureServiceConfiguration {

    @Value("${PFX_PATH:}")
    private String pfxPath;

    @Value("${PKCS11_LIBRARY:}")
    private String pkcs11LibraryPath;

    @Value("${PKCS11_SLOT:-1}")
    private Long pkcs11Slot;

    @Value("${PKCS11_SLOT_LIST_INDEX:-1}")
    private Long pkcs11SlotIndex;

    @Value("${CERTIFICATE_PIN}")
    private String certificatePin;

    @Value("${CERTIFICATE_SERIAL_NUMBER:}")
    private String certificateSerialNumber;

    @Value("${CERTIFICATE_ALIAS:}")
    private String certificateAlias;

    @Value("${CERTIFICATE_CHAIN_GET_ONLINE:true}")
    private boolean certificateChainGetOnline;

    @Value("${ISSUER_CERTIFICATE_PATH:/}")
    private String issuerCertificatePath;

    @Value("${CA_CERTIFICATE_PATH:/}")
    private String caCertificatePath;

    @Value("${TS_SERVER_HOST:http://nes.com.tr}")
    private String timeStampServerHost;

    @Value("${TS_DIGEST_ALGORITHM:SHA-256}")
    private String timeStampDigestAlgorithm;

    @Value("${TS_USER_ID:0}")
    private String timeStampUserId;

    @Value("${TS_USER_PASSWORD:0}")
    private String timeStampUserPassword;

    @Value("${IS_TUBITAK_TSP:false}")
    private boolean isTubitakTsp;

    @Value("${MA3API_LICENSE_PATH:0}")
    private String ma3apiLicensePath;

    @Value("${MAX_SESSION_COUNT:5}")
    private int maxSessionCount;


    @Value("${CERTSTORE_PATH:SertifikaDeposu.svt}")
    private String certStorePath;

    public String getPkcs11LibraryPath() {
        return pkcs11LibraryPath;
    }

    public String getCertificatePin() {
        return certificatePin;
    }

    public String getCertificateSerialNumber() {
        return certificateSerialNumber;
    }

    public String getCertificateAlias() {
        return certificateAlias;
    }

    public Long getPkcs11Slot() {
        return pkcs11Slot;
    }

    public Long getPkcs11SlotIndex() {
        return pkcs11SlotIndex;
    }

    public String getIssuerCertificatePath() {
        return issuerCertificatePath;
    }

    public String getCaCertificatePath() {
        return caCertificatePath;
    }

    public boolean isCertificateChainGetOnline() {
        return certificateChainGetOnline;
    }

    public String getTimeStampServerHost() {
        return timeStampServerHost;
    }

    public String getTimeStampDigestAlgorithm() {
        return timeStampDigestAlgorithm;
    }

    public String getTimeStampUserId() {
        return timeStampUserId;
    }

    public String getTimeStampUserPassword() {
        return timeStampUserPassword;
    }

    public String getMa3apiLicensePath() {
        return ma3apiLicensePath;
    }

    public String getPfxPath() {
        return pfxPath;
    }

    public String getCertStorePath() {
        return certStorePath;
    }

    public int getMaxSessionCount() {
        return maxSessionCount;
    }

    public boolean isTubitakTsp() {
        return isTubitakTsp;
    }
}