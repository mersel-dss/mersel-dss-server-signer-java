package io.mersel.dss.signer.api.services.validation;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Service for validating electronic signatures.
 * Provides detailed validation reports and trust chain analysis.
 */
@Service
public class SignatureValidationService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SignatureValidationService.class);

    private final CertificateVerifier certificateVerifier;

    public SignatureValidationService(CertificateVerifier certificateVerifier) {
        this.certificateVerifier = certificateVerifier;
    }

    /**
     * Validates a signed document and returns validation reports.
     * 
     * @param signedDocument The document to validate
     * @return Validation reports
     */
    public Reports validateDocument(DSSDocument signedDocument) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
        validator.setCertificateVerifier(certificateVerifier);
        return validator.validateDocument();
    }

    /**
     * Validates document and throws exception if validation fails.
     * 
     * @param signedDocument The document to validate
     * @throws SignatureException if validation fails
     */
    public void validateOrFail(DSSDocument signedDocument) {
        Reports reports = validateDocument(signedDocument);
        SimpleReport simpleReport = reports.getSimpleReport();
        DetailedReport detailedReport = reports.getDetailedReport();
        DiagnosticData diagnosticData = reports.getDiagnosticData();

        // Get signature ID (use first signature if multiple exist)
        List<String> signatureIds = simpleReport.getSignatureIdList();
        String signatureId = signatureIds.isEmpty() ? null : signatureIds.get(0);

        validateSignatureOrFail(simpleReport, detailedReport, diagnosticData, signatureId);
    }

    /**
     * Validates signature and throws exception if validation fails.
     * Only signing certificate chain issues are treated as critical.
     * Timestamp TSA chain issues are warnings only.
     */
    private void validateSignatureOrFail(SimpleReport simpleReport,
                                        DetailedReport detailedReport,
                                        DiagnosticData diagnosticData,
                                        String signatureId) {
        List<String> signatureIds = simpleReport.getSignatureIdList();

        if (signatureIds == null || signatureIds.isEmpty()) {
            String error = "Validation failed: No signatures found in document";
            LOGGER.error(error);
            throw new SignatureException("VALIDATION_FAILED", error);
        }

        LOGGER.info("Validating {} signature(s)", signatureIds.size());

        boolean allValid = true;
        StringBuilder errorDetails = new StringBuilder();

        for (String sigId : signatureIds) {
            Indication indication = simpleReport.getIndication(sigId);
            
            LOGGER.debug("Signature {}: Indication = {}", sigId, indication);

            if (indication != Indication.TOTAL_PASSED) {
                allValid = false;
                logCertificateChainDetails(diagnosticData, sigId);
                
                errorDetails.append("\n[Signature: ").append(sigId).append("]");
                errorDetails.append("\n  Indication: ").append(indication);
                
                if (simpleReport.getSubIndication(sigId) != null) {
                    errorDetails.append("\n  SubIndication: ")
                        .append(simpleReport.getSubIndication(sigId));
                }
            } else {
                LOGGER.info("Signature {} validation PASSED", sigId);
            }
        }

        if (!allValid) {
            // Check if failure is only due to timestamp chain issues
            boolean hasSigningCertChainIssue = checkIfSigningCertificateChainHasIssues(
                diagnosticData, signatureIds);

            if (hasSigningCertChainIssue) {
                String fullError = "Signing certificate chain validation failed!" + 
                    errorDetails.toString();
                LOGGER.error(fullError);
                throw new SignatureException("CERTIFICATE_CHAIN_ERROR", fullError);
            } else {
                LOGGER.warn("Validation warnings detected (timestamp TSA chain only)");
                LOGGER.info("Signing certificate chain is valid - signature is acceptable");
            }
        } else {
            LOGGER.info("All signature validations PASSED");
        }
    }

    /**
     * Checks if signing certificate (not timestamp) has chain validation issues.
     */
    private boolean checkIfSigningCertificateChainHasIssues(DiagnosticData diagnosticData,
                                                            List<String> signatureIds) {
        try {
            List<CertificateWrapper> allCerts = diagnosticData.getUsedCertificates();

            // Find KamuSM or TUBİTAK root
            boolean foundKamuSMRoot = false;
            CertificateWrapper kamusmRoot = null;

            for (CertificateWrapper cert : allCerts) {
                String sources = cert.getSources() != null ? cert.getSources().toString() : "";
                String subject = cert.getCertificateDN();

                if (cert.isSelfSigned() &&
                    sources.contains("SIGNATURE") &&
                    !sources.contains("TIMESTAMP") &&
                    (subject.contains("KamuSM") || subject.contains("TÜBİTAK") || 
                     subject.contains("TUBITAK"))) {
                    foundKamuSMRoot = true;
                    kamusmRoot = cert;
                    LOGGER.debug("Found KamuSM/TUBİTAK root: {}", subject);
                    break;
                }
            }

            if (!foundKamuSMRoot) {
                LOGGER.error("No KamuSM/TUBİTAK root found in signing certificate chain");
                return true; // Critical error
            }

            // Check if signing certificate chains to root
            for (CertificateWrapper cert : allCerts) {
                String sources = cert.getSources() != null ? cert.getSources().toString() : "";

                if (!cert.isSelfSigned() &&
                    sources.contains("SIGNATURE") &&
                    !sources.contains("TIMESTAMP") &&
                    !sources.contains("OCSP")) {
                    
                    if (canReachRoot(diagnosticData, cert, kamusmRoot)) {
                        LOGGER.info("Signing certificate chains to trusted root successfully");
                        return false; // All good
                    }
                }
            }

            // Fail-closed: DSS zaten TOTAL_PASSED dışı bir sonuç döndürdü ve imza
            // sertifikasının güvenilir köke ulaştığını gösteremedik. Bu durumu
            // "kabul edilebilir" saymak fail-open olurdu; imza zinciri sorunu say.
            LOGGER.error("Signing certificate chain could not be established to a trusted root");
            return true;

        } catch (Exception e) {
            // Fail-closed: güvenlik analizi sırasında hata olması "geçerli" anlamına
            // gelmez. Doğrulayamadığımız bir zinciri reddediyoruz.
            LOGGER.error("Error checking signing certificate chain, treating as invalid: {}", e.getMessage(), e);
            return true;
        }
    }

    private boolean canReachRoot(DiagnosticData diagnosticData,
                                 CertificateWrapper cert,
                                 CertificateWrapper targetRoot) {
        try {
            if (cert.getId().equals(targetRoot.getId())) {
                return true;
            }

            if (cert.isSelfSigned()) {
                return false;
            }

            String issuerDN = cert.getCertificateIssuerDN();
            List<CertificateWrapper> allCerts = diagnosticData.getUsedCertificates();

            for (CertificateWrapper candidate : allCerts) {
                if (candidate.getCertificateDN().equals(issuerDN)) {
                    return canReachRoot(diagnosticData, candidate, targetRoot);
                }
            }

            return false;

        } catch (Exception e) {
            return false;
        }
    }

    private void logCertificateChainDetails(DiagnosticData diagnosticData, String signatureId) {
        LOGGER.info("Certificate chain analysis:");

        try {
            List<CertificateWrapper> allCerts = diagnosticData.getUsedCertificates();
            LOGGER.info("Found {} certificate(s) in signature", allCerts.size());

            for (CertificateWrapper cert : allCerts) {
                LOGGER.debug("Certificate: Subject={}, Issuer={}, Sources={}, Trusted={}, SelfSigned={}",
                    cert.getCertificateDN(),
                    cert.getCertificateIssuerDN(),
                    cert.getSources(),
                    cert.isTrusted(),
                    cert.isSelfSigned());
            }

        } catch (Exception e) {
            LOGGER.warn("Failed to extract certificate chain details: {}", e.getMessage());
        }
    }
}

