package io.mersel.dss.signer.api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;

import java.nio.charset.StandardCharsets;

/**
 * Properties dosyalarının UTF-8 encoding ile okunmasını sağlar
 */
@Configuration
public class PropertiesEncodingConfiguration {

    @Bean
    public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
        PropertySourcesPlaceholderConfigurer configurer = new PropertySourcesPlaceholderConfigurer();
        // UTF-8 encoding kullan
        configurer.setFileEncoding(StandardCharsets.UTF_8.name());
        return configurer;
    }
}

