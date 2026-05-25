package io.mersel.dss.signer.api.dtos;

public class SignHashDto {
    private String base64EncodedDataToSign;

    public String getBase64EncodedDataToSign() {
        return base64EncodedDataToSign;
    }

    public void setBase64EncodedDataToSign(String base64EncodedDataToSign) {
        this.base64EncodedDataToSign = base64EncodedDataToSign;
    }
}
