package io.mersel.dss.signer.api.dtos;

import javax.validation.constraints.NotBlank;

import org.springframework.web.multipart.MultipartFile;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * CAdES imzalama endpoint'ine gönderilen isteğin veri taşıma nesnesi.
 *
 * <p>Multipart/form-data olarak gönderilir. {@code document} alanı imzalanacak
 * dosyayı, {@code detached} alanı ise imza modunu belirler.</p>
 *
 * <p>Örnek cURL kullanımı:</p>
 * <pre>{@code
 * curl -X POST http://localhost:8080/v1/cadessign \
 *   -F "document=@fatura.xml" \
 *   -F "detached=true"
 * }</pre>
 */
public class SignCadesDto {

    /**
     * İmzalanacak dosya. Format kısıtlaması yoktur; CAdES her türlü
     * binary ve text içeriği imzalayabilir.
     */
    private MultipartFile Document;

    /**
     * İmza modu seçimi.
     * {@code true} → detached: yalnızca imza üretilir, orijinal dosya ayrı kalır.
     * {@code false} veya {@code null} → attached: dosya CMS zarfının içine gömülür.
     */
    private Boolean Detached;

    @Schema(description = "İmzalanacak dosya (zorunlu). Her türlü dosya formatı kabul edilir.",
            required = true)
    public MultipartFile getDocument() {
        return Document;
    }

    @NotBlank
    public void setDocument(MultipartFile document) {
        Document = document;
    }

    @Schema(description = "true ise detached imza (ayrık), false ise attached imza (gömülü). Varsayılan: false",
            example = "false")
    public Boolean getDetached() {
        return Detached;
    }

    public void setDetached(Boolean detached) {
        Detached = detached;
    }
}