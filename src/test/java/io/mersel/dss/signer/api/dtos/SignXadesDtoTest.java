package io.mersel.dss.signer.api.dtos;

import io.mersel.dss.signer.api.models.enums.XadesSignatureLevel;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * {@link SignXadesDto} DTO katmanı kontrat testleri.
 *
 * <p>Buradaki testler controller veya service'i ilgilendirmez; doğrudan DTO'nun
 * "<em>SignatureLevel asla null olamaz</em>" kontratını doğrular. Multipart form
 * binding, JSON deserialize veya manuel setter çağrıları gibi tüm yollardan
 * gelen null değerlerin {@link XadesSignatureLevel#XADES_BES} fallback'ine
 * düşürülmesi gerekir.</p>
 */
@Epic("API Contract")
@Feature("SignXadesDto")
@Severity(SeverityLevel.NORMAL)
class SignXadesDtoTest {

    @Test
    @DisplayName("Default ctor sonrası SignatureLevel non-null ve XADES_BES'tir")
    void defaultConstructorYieldsXADES_BES() {
        SignXadesDto dto = new SignXadesDto();

        assertEquals(XadesSignatureLevel.XADES_BES, dto.getSignatureLevel(),
                "Field initializer XADES_BES atamalı — non-null kontratının ilk garantisi");
    }

    @Test
    @DisplayName("Setter'a null geçirildiğinde alan XADES_BES'e düşürülür (multipart binding savunması)")
    void setterNullFallsBackToXADES_BES() {
        SignXadesDto dto = new SignXadesDto();
        dto.setSignatureLevel(null);

        assertEquals(XadesSignatureLevel.XADES_BES, dto.getSignatureLevel(),
                "Setter null-guard kontratı: alan asla null kalmamalı");
    }

    @Test
    @DisplayName("Setter'a explicit XADES_A geçirildiğinde değer korunur")
    void setterExplicitXADES_AIsPreserved() {
        SignXadesDto dto = new SignXadesDto();
        dto.setSignatureLevel(XadesSignatureLevel.XADES_A);

        assertEquals(XadesSignatureLevel.XADES_A, dto.getSignatureLevel(),
                "Setter null-guard fonksiyonel değerleri override etmemeli");
    }

    @Test
    @DisplayName("Setter'a explicit XADES_BES geçirildiğinde değer korunur")
    void setterExplicitXADES_BESIsPreserved() {
        SignXadesDto dto = new SignXadesDto();
        dto.setSignatureLevel(XadesSignatureLevel.XADES_BES);

        assertEquals(XadesSignatureLevel.XADES_BES, dto.getSignatureLevel());
    }
}
