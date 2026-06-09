package io.mersel.dss.signer.api.services.keystore.iaik.bridge;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mersel.dss.signer.api.dtos.CertificateInfoDto;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Wire üzerinde taşınan zengin tipleri (X.509 sertifika, sertifika zinciri,
 * {@link CertificateInfoDto} listesi) byte dizisine çevirir ve geri okur.
 *
 * <p>Sertifikalar DER ({@code getEncoded()}) olarak; DTO listesi Jackson JSON
 * ile taşınır (Jackson zaten classpath'te). Bunların hepsi küçük payload'lar —
 * imza/digest baytları doğrudan {@link Pkcs11WireProtocol.PayloadWriter#writeBytes}
 * ile geçer.</p>
 */
public final class WireCodec {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private WireCodec() {
    }

    public static byte[] encodeCert(X509Certificate cert) {
        try {
            return cert.getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Sertifika DER encode edilemedi", e);
        }
    }

    public static X509Certificate decodeCert(byte[] der) {
        if (der == null) {
            return null;
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new IllegalStateException("Sertifika DER decode edilemedi", e);
        }
    }

    public static byte[] encodeCertChain(List<X509Certificate> chain) {
        Pkcs11WireProtocol.PayloadWriter w = Pkcs11WireProtocol.newPayload();
        w.writeInt(chain == null ? 0 : chain.size());
        if (chain != null) {
            for (X509Certificate c : chain) {
                w.writeBytes(encodeCert(c));
            }
        }
        return w.toByteArray();
    }

    public static List<X509Certificate> decodeCertChain(byte[] payload) {
        Pkcs11WireProtocol.PayloadReader r = new Pkcs11WireProtocol.PayloadReader(payload);
        int n = r.readInt();
        List<X509Certificate> chain = new ArrayList<>(Math.max(0, n));
        for (int i = 0; i < n; i++) {
            chain.add(decodeCert(r.readBytes()));
        }
        return chain;
    }

    public static byte[] encodeCertInfoList(List<CertificateInfoDto> list) {
        try {
            return MAPPER.writeValueAsBytes(list);
        } catch (Exception e) {
            throw new IllegalStateException("CertificateInfoDto listesi JSON encode edilemedi", e);
        }
    }

    public static List<CertificateInfoDto> decodeCertInfoList(byte[] json) {
        try {
            CertificateInfoDto[] arr = MAPPER.readValue(json, CertificateInfoDto[].class);
            List<CertificateInfoDto> list = new ArrayList<>(arr.length);
            for (CertificateInfoDto dto : arr) {
                list.add(dto);
            }
            return list;
        } catch (Exception e) {
            throw new IllegalStateException("CertificateInfoDto listesi JSON decode edilemedi", e);
        }
    }
}
