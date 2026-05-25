package io.mersel.dss.signer.api.dtos;

public class SignHashResponseDto {
    private String base64EncodedSignedData;

    public SignHashResponseDto() {
    }

    public SignHashResponseDto(String base64EncodedSignedData){
        this.base64EncodedSignedData = base64EncodedSignedData;
    }

    public String getBase64EncodedSignedData() {
        return base64EncodedSignedData;
    }

    public void setBase64EncodedSignedData(String base64EncodedSignedData) {
        this.base64EncodedSignedData = base64EncodedSignedData;
    }
}
