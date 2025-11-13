package eu.europa.esig.dss.xades.signature;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;

import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.Extension;

// ########################OVERRIDE_DSS#########################
// #####  DİKKAT: OVERRIDE DEĞİLDİR!                        ####
// #####  Bu yardımcı metot, XAdES kapsüllü değerler için   ####
// #####  Tübitak’ın belirttiği şekilde 76 karakterde bir   ####
// #####  satır sonu ekleyerek Base64 formatlar.            ####
// #####  Standart Base64 kodlamayı, satır sonlu şekilde    ####
// #####  üretmek için kullanılmalıdır.                     ####
// #############################################################
//
// @param data  Base64 ile kodlanacak ikili veri
// @return      76 karakterde bir satır sonlu Base64 metin

/**
 * Utility class for common XAdES operations.
 * Provides reusable methods for Base64 encoding and XML element creation.
 */
public class XadesUtil {

    /**
     * The standard encoding URI for DER-encoded certificates and revocation data.
     */
    public static final String DER_ENCODING_URI = "http://uri.etsi.org/01903/v1.2.2#DER";

    /**
     * Formats binary data with Base64 encoding using 76-character line breaks.
     * This is the standard format for XAdES encapsulated values.
     * 
     * CRITICAL: Apache Commons Codec Base64 is NOT thread-safe!
     * It maintains internal buffers that can be corrupted during concurrent access.
     * We MUST create a new instance for each call to avoid data corruption.
     * 
     * @param data The binary data to encode
     * @return Base64 encoded string with line breaks
     */
    public static String formatWithBase64(byte[] data) {
        // Create new instance for each call - Base64 is NOT thread-safe!
        // Internal buffer corruption can occur with concurrent encoding
        Base64 encoder = new Base64(76, new byte[] { '\n' });
        return encoder.encodeToString(data);
    }

    /**
     * Creates an EncapsulatedX509Certificate element with properly formatted Base64
     * content.
     * 
     * @param documentDom     The parent document
     * @param parentElement   The parent element to append to
     * @param xadesNamespace  The XAdES namespace to use
     * @param certificateData The DER-encoded certificate bytes
     * @return The created Element
     */
    public static Element createEncapsulatedCertificateElement(
            Document documentDom,
            Element parentElement,
            DSSNamespace xadesNamespace,
            byte[] certificateData) {

        String formattedCert = formatWithBase64(certificateData);

        Element certElement = documentDom.createElementNS(
                xadesNamespace.getUri(),
                xadesNamespace.getPrefix() + ":EncapsulatedX509Certificate");

        certElement.setAttribute("Encoding", DER_ENCODING_URI);
        certElement.setTextContent(formattedCert);
        parentElement.appendChild(certElement);

        return certElement;
    }

    /**
     * Creates an EncapsulatedCRLValue element with properly formatted Base64
     * content.
     * 
     * @param documentDom    The parent document
     * @param parentElement  The parent element to append to
     * @param xadesNamespace The XAdES namespace to use
     * @param crlData        The DER-encoded CRL bytes
     * @return The created Element
     */
    public static Element createEncapsulatedCRLElement(
            Document documentDom,
            Element parentElement,
            DSSNamespace xadesNamespace,
            byte[] crlData) {

        String formattedCRL = formatWithBase64(crlData);

        Element crlElement = documentDom.createElementNS(
                xadesNamespace.getUri(),
                xadesNamespace.getPrefix() + ":EncapsulatedCRLValue");

        crlElement.setAttribute("Encoding", DER_ENCODING_URI);
        crlElement.setTextContent(formattedCRL);
        parentElement.appendChild(crlElement);

        return crlElement;
    }

    /**
     * Creates an EncapsulatedOCSPValue element with properly formatted Base64
     * content.
     * 
     * @param documentDom    The parent document
     * @param parentElement  The parent element to append to
     * @param xadesNamespace The XAdES namespace to use
     * @param ocspData       The DER-encoded OCSP response bytes
     * @return The created Element
     */
    public static Element createEncapsulatedOCSPElement(
            Document documentDom,
            Element parentElement,
            DSSNamespace xadesNamespace,
            byte[] ocspData) {

        String formattedOCSP = formatWithBase64(ocspData);

        Element ocspElement = documentDom.createElementNS(
                xadesNamespace.getUri(),
                xadesNamespace.getPrefix() + ":EncapsulatedOCSPValue");

        ocspElement.setAttribute("Encoding", DER_ENCODING_URI);
        ocspElement.setTextContent(formattedOCSP);
        parentElement.appendChild(ocspElement);

        return ocspElement;
    }

    /**
     * Creates an EncapsulatedTimeStamp element with properly formatted Base64
     * content.
     * 
     * @param documentDom    The parent document
     * @param parentElement  The parent element to append to
     * @param xadesNamespace The XAdES namespace to use
     * @param timestampData  The DER-encoded timestamp token bytes
     * @return The created Element
     */
    public static Element createEncapsulatedTimestampElement(
            Document documentDom,
            Element parentElement,
            DSSNamespace xadesNamespace,
            byte[] timestampData) {

        String formattedTimestamp = formatWithBase64(timestampData);

        Element timestampElement = documentDom.createElementNS(
                xadesNamespace.getUri(),
                xadesNamespace.getPrefix() + ":EncapsulatedTimeStamp");

        timestampElement.setTextContent(formattedTimestamp);
        parentElement.appendChild(timestampElement);

        return timestampElement;
    }

    /**
     * Extracts the CRL Number extension from an X509CRL object using Bouncy Castle.
     * This method correctly handles the ASN.1/DER structure where the INTEGER value
     * is encapsulated within an OCTET STRING.
     *
     * @param crl The X509CRL object to be processed.
     * @return The String representation of the CRL Number.
     * @throws IOException              If an error occurs during ASN.1/DER parsing.
     * @throws IllegalArgumentException If the CRL Number extension is not found or
     *                                  has an invalid structure.
     */
    public static String extractCrlNumber(X509CRL crl) throws IOException, IllegalArgumentException {

        // 1. Retrieve the raw DER-encoded value of the CRL Number extension (OID:
        // 2.5.29.20).
        // Using Extension.cRLNumber.getId() is cleaner than hardcoding the OID string.
        byte[] extensionValue = crl.getExtensionValue(Extension.cRLNumber.getId());

        if (extensionValue == null) {
            throw new IllegalArgumentException(
                    "CRL Number extension (" + Extension.cRLNumber.getId() + ") not found in the CRL.");
        }

        // --- Bouncy Castle ASN.1/DER Decoding ---

        // Step 1: The value returned by getExtensionValue() is the DER encoding
        // of an OCTET STRING that wraps the actual CRL Number INTEGER.
        ASN1OctetString octetString;
        try {
            // Decode the outer layer (the wrapper OCTET STRING).
            octetString = (ASN1OctetString) ASN1Primitive.fromByteArray(extensionValue);
        } catch (ClassCastException e) {
            throw new IOException("The outer layer of the CRL extension is not an expected OCTET STRING.", e);
        }

        // Step 2: Decode the contents of the OCTET STRING, which should be the ASN.1
        // INTEGER.
        try (ASN1InputStream aIn = new ASN1InputStream(octetString.getOctets())) {

            // Read the first object inside the OCTET STRING (which should be the INTEGER).
            ASN1Primitive primitive = aIn.readObject();

            if (!(primitive instanceof ASN1Integer)) {
                throw new IOException("The content of the CRL Number extension is not the expected INTEGER type.");
            }

            // Retrieve the BigInteger value from the ASN1Integer object.
            BigInteger crlNumber = ((ASN1Integer) primitive).getPositiveValue();

            return crlNumber.toString();
        }
    }


    public static String ecPublicKeyToUncompressedPointBase64(ECPublicKey pub) {
        ECPoint w = pub.getW();
        BigInteger x = w.getAffineX();
        BigInteger y = w.getAffineY();

        int fieldSize = pub.getParams().getCurve().getField().getFieldSize();
        int coordLen = (fieldSize + 7) / 8;

        byte[] xb = toFixedLength(x.toByteArray(), coordLen);
        byte[] yb = toFixedLength(y.toByteArray(), coordLen);

        byte[] out = new byte[1 + xb.length + yb.length];
        out[0] = 0x04; // uncompressed point indicator
        System.arraycopy(xb, 0, out, 1, xb.length);
        System.arraycopy(yb, 0, out, 1 + xb.length, yb.length);

        return java.util.Base64.getEncoder().encodeToString(out);
    }

    private static byte[] toFixedLength(byte[] src, int len) {
        // src may contain leading zero due to BigInteger sign bit; normalize to exactly len bytes
        if (src.length == len) return src;
        if (src.length == len + 1 && src[0] == 0x00) {
            return Arrays.copyOfRange(src, 1, src.length);
        }
        if (src.length < len) {
            byte[] dst = new byte[len];
            System.arraycopy(src, 0, dst, len - src.length, src.length);
            return dst;
        }
        // src.length > len -> trim leading bytes (shouldn't happen for proper coords)
        return Arrays.copyOfRange(src, src.length - len, src.length);
    }

    public static String extractNamedCurveOID(ECPublicKey publicKey) {
        try {
            byte[] encoded = publicKey.getEncoded();
            int found = 0;
            for (int i = 0; i < encoded.length - 2; i++) {
                if (encoded[i] == 0x06) { // OBJECT IDENTIFIER
                    int len = encoded[i + 1] & 0xFF;
                    byte[] oidBytes = Arrays.copyOfRange(encoded, i + 2, i + 2 + len);
                    String oid = decodeOID(oidBytes);
                    found++;
                    // 2. OID genellikle curve OID’dir
                    if (found == 2) {
                        return oid;
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }
        int fs = publicKey.getParams().getCurve().getField().getFieldSize();
        switch (fs) {
            case 256:
                return "1.2.840.10045.3.1.7";
            case 384:
                return "1.3.132.0.34"; // secp384r1
            case 521:
                return "1.3.132.0.35";
        }
        return null;
    }

    private static String decodeOID(byte[] bytes) {
        StringBuilder oid = new StringBuilder();
        int first = bytes[0] & 0xFF;
        oid.append(first / 40).append('.').append(first % 40);
        long value = 0;
        for (int i = 1; i < bytes.length; i++) {
            int b = bytes[i] & 0xFF;
            if ((b & 0x80) != 0) {
                value = (value << 7) | (b & 0x7F);
            } else {
                value = (value << 7) | b;
                oid.append('.').append(value);
                value = 0;
            }
        }
        return oid.toString();
    }
}
