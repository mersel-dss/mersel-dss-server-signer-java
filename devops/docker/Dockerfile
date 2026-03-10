# Multi-stage Dockerfile for Sign API
# Stage 1: Build
FROM maven:3.8-openjdk-8 AS builder

WORKDIR /build

# Copy pom.xml and local lib (for dependency resolution)
COPY pom.xml .
COPY src/main/lib ./src/main/lib

# Install local dependencies (sunpkcs11.jar) to Maven local repo
RUN mvn validate -B

# Download remote dependencies (cache layer)
RUN mvn dependency:go-offline -B

# Copy rest of source code
COPY src ./src

# Build application
RUN mvn clean package -DskipTests -B

# Stage 2: Runtime
FROM eclipse-temurin:8-jre

LABEL maintainer="Mersel <info@mersel.io>"
LABEL description="Mersel DSS Signer API - Dijital İmza Servisi"
LABEL version="0.1.0"

# Install required packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app user (security best practice)
RUN groupadd -r signapi && useradd -r -g signapi signapi

# Create directories
RUN mkdir -p /app/logs /app/certs /app/config && \
    chown -R signapi:signapi /app

WORKDIR /app

# Copy jar from builder stage
COPY --from=builder /build/target/mersel-dss-signer-api-*.jar /app/app.jar

# Copy configuration files
COPY --chown=signapi:signapi src/main/resources/application.properties /app/config/
COPY --chown=signapi:signapi src/main/resources/logback-spring.xml /app/config/

# Copy test certificates (trusted root compatible, for development/testing)
# Naming convention: {name}_{algo}@{domain}_{password}.pfx
COPY --chown=signapi:signapi resources/test-cert[s]/ /app/test-certs/

# Switch to non-root user
USER signapi

# Expose ports
EXPOSE 8085

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:8085/actuator/health || exit 1

# Environment variables with defaults
# Defaults: testkurum01 RSA-2048 test cert (trusted root compatible)
# Override at runtime: docker run -e PFX_PATH=... -e CERTIFICATE_PIN=... -e CERTIFICATE_ALIAS=...
ENV SERVER_PORT=8085 \
    LOG_PATH=/app/logs \
    JAVA_OPTS="-Xmx512m -Xms256m" \
    SPRING_PROFILES_ACTIVE=production \
    PFX_PATH=/app/test-certs/testkurum01_rsa2048@test.com.tr_614573.pfx \
    CERTIFICATE_PIN=614573 \
    CERTIFICATE_ALIAS=1

# Run application
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -Djava.security.egd=file:/dev/./urandom -jar /app/app.jar"]

