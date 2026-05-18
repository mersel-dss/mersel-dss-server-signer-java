package io.mersel.dss.signer.api.services.timestamp;

import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import io.mersel.dss.signer.api.exceptions.TimestampException;
import io.mersel.dss.signer.api.services.timestamp.tubitak.TubitakTimestampDataLoader;
import io.mersel.dss.signer.api.services.timestamp.tubitak.TubitakTspDetector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.net.URI;

/**
 * Zaman damgası sunucularını yapılandıran ve yöneten servis.
 * <p>
 * Standart RFC 3161 TSP sunucularının yanı sıra TÜBİTAK ESYA
 * zaman damgası sunucusunu da destekler.
 */
@Service
public class TimestampConfigurationService {

    private static final Logger LOGGER = LoggerFactory.getLogger(TimestampConfigurationService.class);

    private final String tspServerUrl;
    private final String tspUserId;
    private final String tspUserPassword;
    private final boolean isTubitakTsp;
    
    private volatile OnlineTSPSource tspSource;
    private volatile boolean configured = false;

    public TimestampConfigurationService(
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
                    "({}) KamuSM zaman damgası endpoint'i; TÜBİTAK modu otomatik aktif edildi.",
                    tspServerUrl);
        }
    }

    /**
     * TSP kaynağını yapılandırır ve döndürür.
     * Yapılandırma bir kez yapılır ve cache'lenir.
     * 
     * @return Yapılandırılmış OnlineTSPSource
     * @throws TimestampException Yapılandırma başarısız olursa
     */
    public OnlineTSPSource getTspSource() {
        if (!StringUtils.hasText(tspServerUrl)) {
            throw new TimestampException(
                "Timestamp sunucu URL'si yapılandırılmamış. TS_SERVER_HOST property'sini ayarlayın.");
        }

        if (configured) {
            return tspSource;
        }

        synchronized (this) {
            if (configured) {
                return tspSource;
            }

            try {
                TimestampDataLoader dataLoader;
                
                if (isTubitakTsp) {
                    dataLoader = configureTubitakAuthentication();
                } else {
                    dataLoader = new TimestampDataLoader();
                    if (StringUtils.hasText(tspUserId)) {
                        configureStandardAuthentication(dataLoader);
                    }
                }

                tspSource = new OnlineTSPSource(tspServerUrl, dataLoader);
                configured = true;

                LOGGER.info("Timestamp sunucusu yapılandırıldı: {} (Tip: {})", 
                        tspServerUrl, isTubitakTsp ? "TÜBİTAK" : "Standart");
                return tspSource;

            } catch (Exception e) {
                throw new TimestampException(
                    "Timestamp sunucusu yapılandırılamadı: " + tspServerUrl, e);
            }
        }
    }

    /**
     * Timestamp servisinin kullanılabilir ve yapılandırılmış olup olmadığını kontrol eder.
     */
    public boolean isAvailable() {
        return StringUtils.hasText(tspServerUrl);
    }

    /**
     * TÜBİTAK zaman damgası sunucusu için DataLoader yapılandırır.
     */
    private TimestampDataLoader configureTubitakAuthentication() {
        if (!StringUtils.hasText(tspUserId)) {
            throw new TimestampException(
                "TÜBİTAK TSP için kullanıcı ID gerekli. TS_USER_ID ayarlayın.");
        }
        
        if (!StringUtils.hasText(tspUserPassword)) {
            throw new TimestampException(
                "TÜBİTAK TSP için parola gerekli. TS_USER_PASSWORD ayarlayın.");
        }

        try {
            int customerId = Integer.parseInt(tspUserId);
            TubitakTimestampDataLoader dataLoader = new TubitakTimestampDataLoader(
                    customerId,
                    tspUserPassword
            );
            
            LOGGER.info("TÜBİTAK timestamp yapılandırıldı. Kullanıcı ID: {}", customerId);
            return dataLoader;
            
        } catch (NumberFormatException e) {
            throw new TimestampException(
                "Kullanıcı ID sayısal olmalı: " + tspUserId, e);
        }
    }

    /**
     * Standart HTTP Basic Auth yapılandırır.
     */
    private void configureStandardAuthentication(TimestampDataLoader dataLoader) {
        try {
            URI tspUri = URI.create(tspServerUrl);
            int port = tspUri.getPort();
            
            if (port < 0) {
                port = "https".equalsIgnoreCase(tspUri.getScheme()) ? 443 : 80;
            }

            char[] password = StringUtils.hasText(tspUserPassword)
                ? tspUserPassword.toCharArray()
                : new char[0];

            dataLoader.addAuthentication(
                tspUri.getHost(), 
                port, 
                tspUri.getScheme(),
                tspUserId, 
                password);
            dataLoader.setPreemptiveAuthentication(true);

            LOGGER.debug("HTTP Basic Auth yapılandırıldı. Kullanıcı: {}", tspUserId);

        } catch (Exception e) {
            LOGGER.warn("Kimlik doğrulama yapılandırılamadı: {}", e.getMessage());
        }
    }
}

