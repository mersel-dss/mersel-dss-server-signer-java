package io.mersel.dss.signer.api.config;

import javax.annotation.PostConstruct;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.xipki.pkcs11.wrapper.Logger;
import org.xipki.pkcs11.wrapper.StaticLogger;

/**
 * ipkcs11wrapper'ın kendi {@link Logger} interface'ini SLF4J'e köprüler.
 *
 * <p>Library default'ta {@link StaticLogger} içinde Logger inject edilmemişse
 * {@code System.out.println} fallback'ine düşer; bu yüzden Spring Boot
 * Logback config'inden görünmez. Bu bridge'i kurduktan sonra tüm
 * ipkcs11wrapper logları {@code org.xipki.pkcs11.wrapper} kategorisi altında
 * Logback'e akar ve standart logger-level kontrolüne tabi olur.</p>
 *
 * <p><b>Lisans notu:</b> Bu bridge'i kurmak ve startup banner'ı Logback
 * üzerinden WARN'a çekmek IAIK PKCS#11 Wrapper License'ın <em>advertising
 * clause</em>'una aykırı değildir; çünkü zorunlu attribution
 * {@code META-INF/licenses/NOTICE} ve kaynak dosya başlıklarında zaten
 * korunmaktadır. Runtime banner library yazarının ekstra inisiyatifidir,
 * Spring Boot banner'ı gibi suppress edilebilir.</p>
 */
@Configuration
public class Pkcs11WrapperSlf4jBridge {

    @PostConstruct
    void wireSlf4jLogger() {
        StaticLogger.setLogger(new Slf4jAdapter(
                LoggerFactory.getLogger("org.xipki.pkcs11.wrapper")));
    }

    private static final class Slf4jAdapter implements Logger {

        private final org.slf4j.Logger delegate;

        private Slf4jAdapter(org.slf4j.Logger delegate) {
            this.delegate = delegate;
        }

        @Override
        public void info(String format, Object... arguments) {
            delegate.info(format, arguments);
        }

        @Override
        public void warn(String format, Object... arguments) {
            delegate.warn(format, arguments);
        }

        @Override
        public void error(String format, Object... arguments) {
            delegate.error(format, arguments);
        }

        @Override
        public void debug(String format, Object... arguments) {
            delegate.debug(format, arguments);
        }

        @Override
        public void trace(String format, Object... arguments) {
            delegate.trace(format, arguments);
        }

        @Override
        public boolean isDebugEnabled() {
            return delegate.isDebugEnabled();
        }

        @Override
        public boolean isInfoEnabled() {
            return delegate.isInfoEnabled();
        }

        @Override
        public boolean isWarnEnabled() {
            return delegate.isWarnEnabled();
        }

        @Override
        public boolean isTraceEnabled() {
            return delegate.isTraceEnabled();
        }
    }
}
