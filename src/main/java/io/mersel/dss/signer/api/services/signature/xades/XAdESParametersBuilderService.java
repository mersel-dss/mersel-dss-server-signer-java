package io.mersel.dss.signer.api.services.signature.xades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.dataobject.DSSDataObjectFormat;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.models.enums.DocumentType;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * XAdES imza parametrelerini oluşturan servis.
 * Tüm XAdES parametre yapılandırma mantığını kapsar.
 */
@Service
public class XAdESParametersBuilderService {

    private static final String C14N_INCLUSIVE_WITH_COMMENTS = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";

    private final DigestAlgorithmResolverService digestAlgorithmResolver;

    public XAdESParametersBuilderService(DigestAlgorithmResolverService digestAlgorithmResolver) {
        this.digestAlgorithmResolver = digestAlgorithmResolver;
    }

    /**
     * Verilen belge ve imzalama materyali için XAdES imza parametrelerini
     * oluşturur.
     * 
     * @param document     İmzalanacak XML belgesi
     * @param documentType Belge tipi (UBL, e-Arşiv vb.)
     * @param signatureId  İsteğe bağlı imza ID'si
     * @param material     Sertifika ve anahtar içeren imzalama materyali
     * @return Yapılandırılmış XAdESSignatureParameters
     */
    public XAdESSignatureParameters buildParameters(Document document,
            DocumentType documentType,
            String signatureId,
            SigningMaterial material) {
        XAdESSignatureParameters params = new XAdESSignatureParameters();

        // Kök belge
        params.setRootDocument(document);
        params.setSignaturePackaging(SignaturePackaging.ENVELOPED);

        // İmza seviyesi (XAdES-BES baseline)
        params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        // Digest algoritmaları
        DigestAlgorithm digestAlgorithm = digestAlgorithmResolver.resolveDigestAlgorithm(
                material.getSigningCertificate());
        params.setDigestAlgorithm(digestAlgorithm);
        params.setSigningCertificateDigestMethod(digestAlgorithm);
        params.setTokenReferencesDigestAlgorithm(digestAlgorithm);

        // Kanonikalizasyon yöntemleri
        params.setSignedInfoCanonicalizationMethod(C14N_INCLUSIVE_WITH_COMMENTS);
        params.setSignedPropertiesCanonicalizationMethod(C14N_INCLUSIVE_WITH_COMMENTS);

        // İmzalama sertifikası ve zincir
        params.setSigningCertificate(material.getPrimaryCertificateToken());
        params.setCertificateChain(material.getCertificateTokens());
        params.setCheckCertificateRevocation(true);

        // KeyInfo yapılandırması
        params.setSignKeyInfo(false);
        params.setAddX509SubjectName(true);
        params.bLevel().setTrustAnchorBPPolicy(true);
        params.setEn319132(false);

        // B-Level parametreleri
        params.bLevel().setSigningDate(new Date());

        // UBL'ye özgü parametreler
        if (documentType == DocumentType.UblDocument) {
            params.bLevel().setClaimedSignerRoles(Collections.singletonList("Supplier"));
        }

        // Deterministik ID (signatureId verilmişse kullan).
        // SignatureIdNormalizer hem '#' temizler, hem çift "Signature_" prefix'i
        // önler, hem de sonucun XML NCName kuralına uyduğunu doğrular. Bu
        // doğrulama önemlidir çünkü deterministicId aşağıdaki ID/URI'lerin
        // hepsine doğrudan basılır:
        //   <ds:Signature Id="{id}">
        //   <ds:Reference URI="#xades-{id}">
        //   <xades:SignedProperties Id="xades-{id}">
        //   <xades:QualifyingProperties Target="#{id}">
        // İçinde '#' olan bir id, RFC 3986 fragment kurallarını ihlal eder
        // (URI'da iki '#' arda arda yasaktır) ve TÜBİTAK/GİB doğrulayıcısı
        // SignedProperties node'unu çözemediği için imzayı geçersiz işaretler.
        String normalizedId = SignatureIdNormalizer.normalize(signatureId);
        if (normalizedId != null) {
            params.getContext().setDeterministicId(normalizedId);
        }

        // Referanslar
        List<DSSReference> references = buildReferences(digestAlgorithm);
        params.setReferences(references);

        // Veri nesnesi formatı
        params.setDataObjectFormatList(buildDataObjectFormats(references));

        return params;
    }

    /**
     * İmza için referansları oluşturur.
     */
    private List<DSSReference> buildReferences(DigestAlgorithm digestAlgorithm) {
        List<DSSReference> references = new ArrayList<>();

        DSSReference docRef = new DSSReference();
        String documentReferenceId = "Reference-Id-" + UUID.randomUUID();
        docRef.setId(documentReferenceId);
        docRef.setUri(""); // Enveloped signature
        docRef.setDigestMethodAlgorithm(digestAlgorithm);

        // Dönüşümler
        List<DSSTransform> transforms = new ArrayList<>();
        transforms.add(new EnvelopedSignatureTransform());
        docRef.setTransforms(transforms);

        references.add(docRef);
        return references;
    }

    /**
     * Veri nesnesi format tanımlayıcılarını oluşturur.
     */
    private List<DSSDataObjectFormat> buildDataObjectFormats(List<DSSReference> references) {
        if (references.isEmpty()) {
            return Collections.emptyList();
        }

        DSSDataObjectFormat dof = new DSSDataObjectFormat();
        dof.setObjectReference("#" + references.get(0).getId());
        dof.setMimeType("text/xml");

        return Collections.singletonList(dof);
    }
}
