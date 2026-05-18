# ☸️ Kubernetes Deployment

> 🚧 **Yakında:** Kubernetes manifest'leri v0.2.0'da eklenecek

## Planlanan Özellikler

### Temel Deployment

- **Deployment** - Sign API pod'ları
- **Service** - ClusterIP/LoadBalancer
- **ConfigMap** - Uygulama yapılandırması
- **Secret** - Sertifika ve şifreler
- **Ingress** - External access

### Monitoring

- **ServiceMonitor** - Prometheus Operator entegrasyonu
- **PrometheusRule** - Alert rules
- **Grafana Dashboard** - ConfigMap olarak

### Scaling & Availability

- **HPA (Horizontal Pod Autoscaler)** - CPU/Memory bazlı scaling
- **PodDisruptionBudget** - High availability
- **Resource Limits** - CPU ve memory quotas

### Storage

- **PersistentVolumeClaim** - Log storage
- **Secret** - Certificate storage (encrypted)

## Örnek Manifest (Preview)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sign-api
  labels:
    app: sign-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: sign-api
  template:
    metadata:
      labels:
        app: sign-api
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8085"
        prometheus.io/path: "/actuator/prometheus"
    spec:
      containers:
      - name: sign-api
        image: mersel-dss-signer-api:0.4.0
        ports:
        - containerPort: 8085
          name: http
        env:
        - name: PFX_PATH
          value: "/app/certs/certificate.pfx"
        - name: CERTIFICATE_PIN
          valueFrom:
            secretKeyRef:
              name: cert-secrets
              key: pin
        - name: CERTIFICATE_ALIAS
          value: "prod-cert"
        livenessProbe:
          httpGet:
            path: /actuator/health
            port: 8085
          initialDelaySeconds: 60
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /actuator/health
            port: 8085
          initialDelaySeconds: 30
          periodSeconds: 5
        resources:
          requests:
            cpu: "500m"
            memory: "1Gi"
          limits:
            cpu: "2"
            memory: "2Gi"
```

---

**v0.2.0'da tam Kubernetes desteği gelecek!**

