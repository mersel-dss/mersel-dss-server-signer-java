package io.mersel.dss.signer.api.constants;

public class XmlConstants {
    // WS-Security Namespaces
    public static String NS_WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    public static String NS_WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

    // WS-Security Attributes
    public static String ATTR_EncodingType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
    public static String ATTR_ValueType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
    public static String ATTR_Soap_1_Dot_2_ValueType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509PKIPathv1";

    // SOAP Namespaces
    public static String NS_SOAP_ENVELOPE = "http://schemas.xmlsoap.org/soap/envelope/";
    public static String NS_SOAP_1_DOT_2_ENVELOPE = "http://www.w3.org/2003/05/soap-envelope";

    // UBL Namespace
    public static String NS_UBL_EXTENSION = "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2";

    // e-Arşiv Namespace
    public static String NS_EARSIV = "http://earsiv.efatura.gov.tr";

    // e-Bilet Namespace
    public static String NS_BILET = "http://ebilet.efatura.gov.tr";

    // HR-XML / Open Applications Namespace
    public static String NS_OAGIS = "http://www.openapplications.org/oagis/9";

    // Signature Algorithm
    public static String SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
}
