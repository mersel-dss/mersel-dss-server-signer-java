package io.mersel.dss.signer.api.controllers;

import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.metrics.SignatureMetrics;
import io.mersel.dss.signer.api.services.signature.xades.SigningMaterialCounterSignatureService;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * {@link UserCounterSignatureController} feature flag'inin
 * ({@code mersel.signer.integrator-countersign.enabled}) varsayılan KAPALI
 * olduğunu ve yalnızca bilinçli olarak {@code true} verildiğinde bean'in
 * oluştuğunu doğrular.
 */
class UserCounterSignatureControllerFeatureFlagTest {

    private static SigningMaterial signingMaterial;

    @BeforeAll
    static void initSigningMaterial() throws Exception {
        // SigningMaterial final — mock'lanamaz; self-signed RSA ile gerçek
        // PFX/JCA materyali kurulur.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        X500Name subject = new X500Name("CN=Feature Flag Test, O=Mersel, C=TR");
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                subject, BigInteger.ONE, notBefore, notAfter, subject,
                SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                        .build(keyPair.getPrivate())));

        signingMaterial = new SigningMaterial(
                keyPair.getPrivate(), cert, Collections.singletonList(cert));
    }

    private ApplicationContextRunner runner() {
        return new ApplicationContextRunner()
                .withBean(SigningMaterialCounterSignatureService.class,
                        () -> mock(SigningMaterialCounterSignatureService.class))
                .withBean(SigningMaterial.class, () -> signingMaterial)
                .withBean(SignatureMetrics.class, () -> mock(SignatureMetrics.class))
                .withUserConfiguration(UserCounterSignatureController.class);
    }

    @Test
    @DisplayName("Property verilmezse endpoint kapalıdır (bean oluşmaz)")
    void disabledByDefault() {
        runner().run(ctx -> assertThat(ctx).doesNotHaveBean(UserCounterSignatureController.class));
    }

    @Test
    @DisplayName("Property 'false' iken endpoint kapalıdır")
    void disabledWhenFalse() {
        runner().withPropertyValues("mersel.signer.integrator-countersign.enabled=false")
                .run(ctx -> assertThat(ctx).doesNotHaveBean(UserCounterSignatureController.class));
    }

    @Test
    @DisplayName("Property 'true' iken endpoint açılır")
    void enabledWhenTrue() {
        runner().withPropertyValues("mersel.signer.integrator-countersign.enabled=true")
                .run(ctx -> assertThat(ctx).hasSingleBean(UserCounterSignatureController.class));
    }
}
