package io.mersel.dss.signer.api.e2e.verifier;

import io.mersel.dss.signer.api.models.SigningMaterial;

/**
 * E2E arka uç matrisi. Ürünün canlı ortam kullanımının ağırlıklı olarak
 * PKCS#11 olması beklendiği için verifier roundtrip testleri hem klasik
 * PFX/JCA yolunu hem de aynı PFX test sertifikalarıyla beslenen PKCS#11
 * imzalama kontratını çalıştırır.
 */
public enum E2eSigningBackend {

    PFX_JCA {
        @Override
        SigningMaterial load(PfxTestKey key) {
            return E2eSigningMaterialFactory.load(key);
        }
    },

    PFX_BACKED_PKCS11 {
        @Override
        SigningMaterial load(PfxTestKey key) {
            return E2eSigningMaterialFactory.loadAsPkcs11(key);
        }
    };

    abstract SigningMaterial load(PfxTestKey key);
}
