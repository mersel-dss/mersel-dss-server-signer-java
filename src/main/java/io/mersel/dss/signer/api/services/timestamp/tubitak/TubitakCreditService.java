package io.mersel.dss.signer.api.services.timestamp.tubitak;

import io.mersel.dss.signer.api.dtos.TubitakCreditResponseDto;
import io.mersel.dss.signer.api.exceptions.TimestampException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 * TÜBİTAK ESYA zaman damgası kontör sorgulama servisi.
 */
@Service
public class TubitakCreditService {

    private static final Logger LOGGER = LoggerFactory.getLogger(TubitakCreditService.class);

    private static final String IDENTITY_HEADER = "identity";
    private static final String CREDIT_REQ_HEADER = "credit_req";
    private static final String CREDIT_REQ_TIME_HEADER = "credit_req_time";
    private static final String USER_AGENT_HEADER = "User-Agent";
    private static final String TUBITAK_USER_AGENT = "UEKAE TSS Client";

    private final String tspServerUrl;
    private final String tspUserId;
    private final String tspUserPassword;
    private final boolean isTubitakTsp;

    public TubitakCreditService(
            @Value("${TS_SERVER_HOST:}") String tspServerUrl,
            @Value("${TS_USER_ID:}") String tspUserId,
            @Value("${TS_USER_PASSWORD:}") String tspUserPassword,
            @Value("${IS_TUBITAK_TSP:false}") boolean isTubitakTsp) {
        this.tspServerUrl = tspServerUrl;
        this.tspUserId = tspUserId;
        this.tspUserPassword = tspUserPassword;
        this.isTubitakTsp = TubitakTspDetector.resolveTubitakTspMode(isTubitakTsp, tspServerUrl);

        if (!isTubitakTsp && this.isTubitakTsp) {
            LOGGER.info("IS_TUBITAK_TSP explicit olarak set edilmemiş, ancak TS_SERVER_HOST " +
                    "({}) KamuSM zaman damgası endpoint'i; kontör servisi TÜBİTAK modunda " +
                    "çalışacak.", tspServerUrl);
        }
    }

    /**
     * TÜBİTAK zaman damgası kontör bilgisini sorgular.
     *
     * @return Kontör bilgisi
     * @throws TimestampException TÜBİTAK modu aktif değilse veya sorgulama başarısız olursa
     */
    public TubitakCreditResponseDto checkCredit() {
        if (!isTubitakTsp) {
            throw new TimestampException(
                    "Kontör sorgulama sadece TÜBİTAK zaman damgası modu için kullanılabilir. " +
                    "IS_TUBITAK_TSP=true olarak ayarlayın.");
        }

        if (!StringUtils.hasText(tspServerUrl)) {
            throw new TimestampException("Timestamp sunucu URL'si yapılandırılmamış.");
        }

        if (!StringUtils.hasText(tspUserId)) {
            throw new TimestampException("Kullanıcı ID yapılandırılmamış.");
        }

        if (!StringUtils.hasText(tspUserPassword)) {
            throw new TimestampException("Kullanıcı parolası yapılandırılmamış.");
        }

        try {
            int customerId = Integer.parseInt(tspUserId);

            // Timestamp (epoch millis)
            long timestamp = System.currentTimeMillis();

            // ÖNEMLİ: SHA1(customerID + timestamp) hesapla
            String authString = String.valueOf(customerId) + String.valueOf(timestamp);
            byte[] authHash = calculateSHA1(authString.getBytes());

            // Bu hash'i şifrele
            String authToken = TubitakAuthenticationHelper.encryptIdentity(
                    customerId,
                    tspUserPassword,
                    authHash
            );

            // HTTP request gönder
            String creditInfo = sendCreditRequest(authToken, customerId, timestamp);

            LOGGER.info("TÜBİTAK kontör sorgulaması başarılı. Müşteri ID: {}", customerId);

            return new TubitakCreditResponseDto(
                    parseCreditFromResponse(creditInfo),
                    customerId,
                    creditInfo
            );

        } catch (NumberFormatException e) {
            throw new TimestampException("Kullanıcı ID sayısal olmalı: " + tspUserId, e);
        } catch (Exception e) {
            LOGGER.error("TÜBİTAK kontör sorgulaması başarısız: {}", e.getMessage());
            LOGGER.debug("Hata detayı", e);
            throw new TimestampException("Kontör sorgulaması başarısız", e);
        }
    }

    /**
     * SHA1 hash hesaplar.
     */
    private byte[] calculateSHA1(byte[] data) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-1");
            return digest.digest(data);
        } catch (Exception e) {
            throw new RuntimeException("SHA-1 hesaplama hatası", e);
        }
    }

    /**
     * Kontör sorgulama HTTP request'i gönderir.
     */
    private String sendCreditRequest(String authToken, int customerId, long timestamp) throws Exception {
        org.apache.http.client.methods.HttpPost httpPost =
                new org.apache.http.client.methods.HttpPost(tspServerUrl);

        httpPost.setHeader("Content-Type", "application/timestamp-query");
        httpPost.setHeader(USER_AGENT_HEADER, TUBITAK_USER_AGENT);
        httpPost.setHeader(IDENTITY_HEADER, authToken);
        httpPost.setHeader(CREDIT_REQ_HEADER, String.valueOf(customerId));
        httpPost.setHeader(CREDIT_REQ_TIME_HEADER, String.valueOf(timestamp));

        httpPost.setEntity(new org.apache.http.entity.ByteArrayEntity(new byte[0]));

        LOGGER.debug("TÜBİTAK kontör sorgulama request gönderiliyor: {}", tspServerUrl);

        org.apache.http.impl.client.CloseableHttpClient httpClient =
                org.apache.http.impl.client.HttpClients.createDefault();

        try (org.apache.http.client.methods.CloseableHttpResponse response =
                     httpClient.execute(httpPost)) {

            int statusCode = response.getStatusLine().getStatusCode();
            LOGGER.debug("HTTP response status: {}", statusCode);

            if (statusCode != 200) {
                throw new RuntimeException("HTTP error: " + statusCode);
            }

            // Response body'yi parse et
            byte[] responseBytes = org.apache.http.util.EntityUtils.toByteArray(
                    response.getEntity());

            // TÜBİTAK kontör bilgisini response'dan çıkar
            // Response ASN.1 formatında olabilir veya özel format olabilir
            return parseResponseForCredit(responseBytes);

        } finally {
            httpClient.close();
        }
    }

    /**
     * Response'dan kontör bilgisini parse eder.
     */
    private String parseResponseForCredit(byte[] responseBytes) {
        // TÜBİTAK plain text olarak kontör dönüyor
        return new String(responseBytes).trim();
    }

    /**
     * Response string'inden kontör sayısını çıkarır.
     */
    private Long parseCreditFromResponse(String response) {
        try {
            // Response direkt sayı olarak geliyor
            return Long.parseLong(response.trim());
        } catch (Exception e) {
            LOGGER.warn("Kontör bilgisi parse edilemedi: {}", e.getMessage());
            return 0L;
        }
    }

    /**
     * Servisin kullanılabilir olup olmadığını kontrol eder.
     */
    public boolean isAvailable() {
        return isTubitakTsp && 
               StringUtils.hasText(tspServerUrl) && 
               StringUtils.hasText(tspUserId) && 
               StringUtils.hasText(tspUserPassword);
    }
}

