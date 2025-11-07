package io.mersel.dss.signer.api.dtos;

import org.springframework.web.multipart.MultipartFile;

import javax.validation.constraints.NotBlank;

public class SignWsSecurityDto {
    private MultipartFile document;
    private Boolean soap1Dot2;

    public MultipartFile getDocument() {
        return document;
    }

    @NotBlank
    public void setDocument(MultipartFile document) {
        this.document = document;
    }


    public Boolean getSoap1Dot2() {
        return soap1Dot2;
    }

    public void setSoap1Dot2(Boolean soap1Dot2) {
        this.soap1Dot2 = soap1Dot2;
    }
}
