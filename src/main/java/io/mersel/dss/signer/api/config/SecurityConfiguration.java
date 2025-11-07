package io.mersel.dss.signer.api.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Arrays;
import java.util.Collections;

/**
 * Web güvenlik yapılandırması.
 * 
 * Not: Bu proje şu anda authentication olmadan çalışmaktadır.
 * Internal kullanım için tasarlanmıştır. Production ortamında
 * network seviyesinde güvenlik sağlanmalıdır.
 */
@Configuration
public class SecurityConfiguration implements WebMvcConfigurer {

    @Value("${cors.allowed-origins:*}")
    private String allowedOrigins;

    @Value("${cors.allowed-methods:GET,POST,PUT,DELETE,OPTIONS}")
    private String allowedMethods;

    @Value("${cors.max-age:3600}")
    private Long maxAge;

    /**
     * Root path'i Swagger UI'ya yönlendir.
     */
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addRedirectViewController("/", "/swagger/index.html");
    }

    /**
     * CORS yapılandırması.
     * 
     * Production ortamında allowed-origins değerini spesifik domain'lerle
     * sınırlandırmanız önerilir.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // Allowed origins - production'da spesifik domain'ler kullanılmalı
        if ("*".equals(allowedOrigins)) {
            configuration.addAllowedOriginPattern("*");
        } else {
            configuration.setAllowedOrigins(Arrays.asList(allowedOrigins.split(",")));
        }
        
        // Allowed HTTP methods
        configuration.setAllowedMethods(Arrays.asList(allowedMethods.split(",")));
        
        // Allowed headers
        configuration.setAllowedHeaders(Arrays.asList(
            "Authorization",
            "Content-Type",
            "X-Requested-With",
            "Accept",
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "X-API-Key"
        ));
        
        // Exposed headers - client tarafından okunabilir
        configuration.setExposedHeaders(Arrays.asList(
            "x-signature-value",
            "Content-Disposition"
        ));
        
        // Credentials
        configuration.setAllowCredentials(true);
        
        // Max age
        configuration.setMaxAge(maxAge);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        
        return source;
    }
}

