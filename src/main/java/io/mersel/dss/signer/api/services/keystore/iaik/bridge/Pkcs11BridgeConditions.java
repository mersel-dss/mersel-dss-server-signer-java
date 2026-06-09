package io.mersel.dss.signer.api.services.keystore.iaik.bridge;

import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * PKCS#11 köprü stratejisine göre bean aktivasyonunu kontrol eden Spring
 * {@link Condition} sınıfları. {@link Pkcs11BridgeDecision} üzerinden karar
 * verir; {@code PKCS11_LIBRARY} ve {@code PKCS11_BRIDGE_MODE} property'lerini
 * Spring {@code Environment}'tan okur (env var + application.properties).
 */
public final class Pkcs11BridgeConditions {

    private Pkcs11BridgeConditions() {
    }

    private static Pkcs11BridgeDecision.Strategy strategy(ConditionContext context) {
        String lib = context.getEnvironment().getProperty("PKCS11_LIBRARY");
        String mode = context.getEnvironment().getProperty("PKCS11_BRIDGE_MODE");
        String helperJava = context.getEnvironment().getProperty("PKCS11_HELPER_JAVA");
        boolean remoteReady = helperJava != null && !helperJava.trim().isEmpty();
        return Pkcs11BridgeDecision.decide(lib, mode, remoteReady);
    }

    /** DLL ana JVM'e doğrudan yüklenecekse aktif. */
    public static final class InProcess implements Condition {
        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            return strategy(context) == Pkcs11BridgeDecision.Strategy.IN_PROCESS;
        }
    }

    /** DLL ayrı bit'likteki helper process'te yüklenecekse aktif. */
    public static final class Remote implements Condition {
        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            return strategy(context) == Pkcs11BridgeDecision.Strategy.REMOTE;
        }
    }
}
