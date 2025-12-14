# BSPDS Production Kubernetes Deployment
> **Warning**: These instructions are untested and theoretical, written from the top of Lewis' head. They may contain errors or omissions. This warning will be removed once the guide has been verified.
This guide covers deploying BSPDS on a production multi-node Kubernetes cluster with high availability, auto-scaling, and proper secrets management.
## Architecture Overview
```
                    ┌─────────────────────────────────────────────────┐
                    │              Kubernetes Cluster                 │
                    │                                                 │
    Internet ──────►│  Ingress Controller (nginx/traefik)             │
                    │         │                                       │
                    │         ▼                                       │
                    │  ┌─────────────┐                                │
                    │  │   Service   │◄── HPA (2-10 replicas)         │
                    │  └──────┬──────┘                                │
                    │         │                                       │
                    │    ┌────┴────┐                                  │
                    │    ▼         ▼                                  │
                    │ ┌─────┐  ┌─────┐                                │
                    │ │BSPDS│  │BSPDS│  ... (pods)                    │
                    │ └──┬──┘  └──┬──┘                                │
                    │    │        │                                   │
                    │    ▼        ▼                                   │
                    │ ┌──────────────────────────────────────┐        │
                    │ │  PostgreSQL  │  MinIO  │  Valkey     │        │
                    │ │  (HA/Operator)│ (StatefulSet) │ (Sentinel)    │
                    │ └──────────────────────────────────────┘        │
                    └─────────────────────────────────────────────────┘
```
## Prerequisites
- Kubernetes cluster (1.30+) with at least 3 nodes (1.34 is current stable)
- `kubectl` configured to access your cluster
- `helm` 3.x installed
- Storage class that supports `ReadWriteOnce` (for databases)
- Ingress controller installed (nginx-ingress or traefik)
- cert-manager installed for TLS certificates
### Quick Prerequisites Setup
If you need to install prerequisites:
```bash
# Install nginx-ingress (chart v4.14.1 - December 2025)
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update
helm install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx --create-namespace \
  --version 4.14.1
# Install cert-manager (v1.19.2 - December 2025)
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace \
  --version v1.19.2 \
  --set installCRDs=true
```
---
## 1. Create Namespace
```bash
kubectl create namespace bspds
kubectl config set-context --current --namespace=bspds
```
## 2. Create Secrets
Generate secure passwords and secrets:
```bash
# Generate secrets
DB_PASSWORD=$(openssl rand -base64 32)
MINIO_PASSWORD=$(openssl rand -base64 32)
JWT_SECRET=$(openssl rand -base64 48)
DPOP_SECRET=$(openssl rand -base64 48)
MASTER_KEY=$(openssl rand -base64 48)
# Create Kubernetes secrets
kubectl create secret generic bspds-db-credentials \
  --from-literal=username=bspds \
  --from-literal=password="$DB_PASSWORD"
kubectl create secret generic bspds-minio-credentials \
  --from-literal=root-user=minioadmin \
  --from-literal=root-password="$MINIO_PASSWORD"
kubectl create secret generic bspds-secrets \
  --from-literal=jwt-secret="$JWT_SECRET" \
  --from-literal=dpop-secret="$DPOP_SECRET" \
  --from-literal=master-key="$MASTER_KEY"
# Save secrets locally (KEEP SECURE!)
echo "DB_PASSWORD=$DB_PASSWORD" > secrets.txt
echo "MINIO_PASSWORD=$MINIO_PASSWORD" >> secrets.txt
echo "JWT_SECRET=$JWT_SECRET" >> secrets.txt
echo "DPOP_SECRET=$DPOP_SECRET" >> secrets.txt
echo "MASTER_KEY=$MASTER_KEY" >> secrets.txt
chmod 600 secrets.txt
```
## 3. Deploy PostgreSQL
### Option A: CloudNativePG Operator (Recommended for HA)
```bash
# Install CloudNativePG operator (v1.28.0 - December 2025)
kubectl apply --server-side -f \
  https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.28/releases/cnpg-1.28.0.yaml
# Wait for operator
kubectl wait --for=condition=available --timeout=120s \
  deployment/cnpg-controller-manager -n cnpg-system
```
```bash
cat <<EOF | kubectl apply -f -
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: bspds-db
  namespace: bspds
spec:
  instances: 3
  postgresql:
    parameters:
      max_connections: "200"
      shared_buffers: "256MB"
  bootstrap:
    initdb:
      database: pds
      owner: bspds
      secret:
        name: bspds-db-credentials
  storage:
    size: 20Gi
    storageClass: standard  # adjust for your cluster
  resources:
    requests:
      memory: "512Mi"
      cpu: "250m"
    limits:
      memory: "1Gi"
      cpu: "1000m"
  affinity:
    podAntiAffinityType: required
EOF
```
### Option B: Simple StatefulSet (Single Instance)
```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: bspds-db-pvc
  namespace: bspds
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 20Gi
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: bspds-db
  namespace: bspds
spec:
  serviceName: bspds-db
  replicas: 1
  selector:
    matchLabels:
      app: bspds-db
  template:
    metadata:
      labels:
        app: bspds-db
    spec:
      containers:
        - name: postgres
          image: postgres:18-alpine
          ports:
            - containerPort: 5432
          env:
            - name: POSTGRES_DB
              value: pds
            - name: POSTGRES_USER
              valueFrom:
                secretKeyRef:
                  name: bspds-db-credentials
                  key: username
            - name: POSTGRES_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: bspds-db-credentials
                  key: password
            - name: PGDATA
              value: /var/lib/postgresql/data/pgdata
          volumeMounts:
            - name: data
              mountPath: /var/lib/postgresql/data
          resources:
            requests:
              memory: "256Mi"
              cpu: "100m"
            limits:
              memory: "1Gi"
              cpu: "500m"
          livenessProbe:
            exec:
              command: ["pg_isready", "-U", "bspds", "-d", "pds"]
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            exec:
              command: ["pg_isready", "-U", "bspds", "-d", "pds"]
            initialDelaySeconds: 5
            periodSeconds: 5
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: bspds-db-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: bspds-db-rw
  namespace: bspds
spec:
  selector:
    app: bspds-db
  ports:
    - port: 5432
      targetPort: 5432
EOF
```
## 4. Deploy MinIO
```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: bspds-minio-pvc
  namespace: bspds
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 50Gi
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: bspds-minio
  namespace: bspds
spec:
  serviceName: bspds-minio
  replicas: 1
  selector:
    matchLabels:
      app: bspds-minio
  template:
    metadata:
      labels:
        app: bspds-minio
    spec:
      containers:
        - name: minio
          image: minio/minio:RELEASE.2025-10-15T17-29-55Z
          args:
            - server
            - /data
            - --console-address
            - ":9001"
          ports:
            - containerPort: 9000
              name: api
            - containerPort: 9001
              name: console
          env:
            - name: MINIO_ROOT_USER
              valueFrom:
                secretKeyRef:
                  name: bspds-minio-credentials
                  key: root-user
            - name: MINIO_ROOT_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: bspds-minio-credentials
                  key: root-password
          volumeMounts:
            - name: data
              mountPath: /data
          resources:
            requests:
              memory: "256Mi"
              cpu: "100m"
            limits:
              memory: "512Mi"
              cpu: "500m"
          livenessProbe:
            httpGet:
              path: /minio/health/live
              port: 9000
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /minio/health/ready
              port: 9000
            initialDelaySeconds: 10
            periodSeconds: 5
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: bspds-minio-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: bspds-minio
  namespace: bspds
spec:
  selector:
    app: bspds-minio
  ports:
    - port: 9000
      targetPort: 9000
      name: api
    - port: 9001
      targetPort: 9001
      name: console
EOF
```
### Initialize MinIO Bucket
```bash
kubectl run minio-init --rm -it --restart=Never \
  --image=minio/mc:RELEASE.2025-07-16T15-35-03Z \
  --env="MINIO_ROOT_USER=minioadmin" \
  --env="MINIO_ROOT_PASSWORD=$(kubectl get secret bspds-minio-credentials -o jsonpath='{.data.root-password}' | base64 -d)" \
  --command -- sh -c "
    mc alias set local http://bspds-minio:9000 \$MINIO_ROOT_USER \$MINIO_ROOT_PASSWORD &&
    mc mb --ignore-existing local/pds-blobs
  "
```
## 5. Deploy Valkey
```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: bspds-valkey-pvc
  namespace: bspds
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 5Gi
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: bspds-valkey
  namespace: bspds
spec:
  serviceName: bspds-valkey
  replicas: 1
  selector:
    matchLabels:
      app: bspds-valkey
  template:
    metadata:
      labels:
        app: bspds-valkey
    spec:
      containers:
        - name: valkey
          image: valkey/valkey:9-alpine
          args:
            - valkey-server
            - --appendonly
            - "yes"
            - --maxmemory
            - "256mb"
            - --maxmemory-policy
            - allkeys-lru
          ports:
            - containerPort: 6379
          volumeMounts:
            - name: data
              mountPath: /data
          resources:
            requests:
              memory: "128Mi"
              cpu: "50m"
            limits:
              memory: "300Mi"
              cpu: "200m"
          livenessProbe:
            exec:
              command: ["valkey-cli", "ping"]
            initialDelaySeconds: 10
            periodSeconds: 5
          readinessProbe:
            exec:
              command: ["valkey-cli", "ping"]
            initialDelaySeconds: 5
            periodSeconds: 3
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: bspds-valkey-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: bspds-valkey
  namespace: bspds
spec:
  selector:
    app: bspds-valkey
  ports:
    - port: 6379
      targetPort: 6379
EOF
```
## 6. Build and Push BSPDS Image
```bash
# Build image
cd /path/to/bspds
docker build -t your-registry.com/bspds:latest .
docker push your-registry.com/bspds:latest
```
If using a private registry, create an image pull secret:
```bash
kubectl create secret docker-registry regcred \
  --docker-server=your-registry.com \
  --docker-username=your-username \
  --docker-password=your-password \
  --docker-email=your-email
```
## 7. Run Database Migrations
BSPDS runs migrations automatically on startup. However, if you want to run migrations separately (recommended for zero-downtime deployments), you can use a Job:
```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: bspds-migrate
  namespace: bspds
spec:
  ttlSecondsAfterFinished: 300
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: migrate
          image: your-registry.com/bspds:latest
          command: ["/usr/local/bin/bspds"]
          args: ["--migrate-only"]  # Add this flag to your app, or remove this Job
          env:
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: bspds-db-credentials
                  key: password
            - name: DATABASE_URL
              value: "postgres://bspds:$(DB_PASSWORD)@bspds-db-rw:5432/pds"
EOF
kubectl wait --for=condition=complete --timeout=120s job/bspds-migrate
```
> **Note**: If your BSPDS image doesn't have a `--migrate-only` flag, you can skip this step. The app will run migrations on first startup. Alternatively, build a separate migration image with `sqlx-cli` installed.
## 8. Deploy BSPDS Application
```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: bspds-config
  namespace: bspds
data:
  PDS_HOSTNAME: "pds.example.com"
  SERVER_HOST: "0.0.0.0"
  SERVER_PORT: "3000"
  S3_ENDPOINT: "http://bspds-minio:9000"
  AWS_REGION: "us-east-1"
  S3_BUCKET: "pds-blobs"
  VALKEY_URL: "redis://bspds-valkey:6379"
  APPVIEW_URL: "https://api.bsky.app"
  CRAWLERS: "https://bsky.network"
  FRONTEND_DIR: "/app/frontend/dist"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bspds
  namespace: bspds
spec:
  replicas: 2
  selector:
    matchLabels:
      app: bspds
  template:
    metadata:
      labels:
        app: bspds
    spec:
      imagePullSecrets:
        - name: regcred  # Remove if using public registry
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchLabels:
                    app: bspds
                topologyKey: kubernetes.io/hostname
      containers:
        - name: bspds
          image: your-registry.com/bspds:latest
          ports:
            - containerPort: 3000
              name: http
          envFrom:
            - configMapRef:
                name: bspds-config
          env:
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: bspds-db-credentials
                  key: password
            - name: DATABASE_URL
              value: "postgres://bspds:$(DB_PASSWORD)@bspds-db-rw:5432/pds"
            - name: AWS_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: bspds-minio-credentials
                  key: root-user
            - name: AWS_SECRET_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: bspds-minio-credentials
                  key: root-password
            - name: JWT_SECRET
              valueFrom:
                secretKeyRef:
                  name: bspds-secrets
                  key: jwt-secret
            - name: DPOP_SECRET
              valueFrom:
                secretKeyRef:
                  name: bspds-secrets
                  key: dpop-secret
            - name: MASTER_KEY
              valueFrom:
                secretKeyRef:
                  name: bspds-secrets
                  key: master-key
          resources:
            requests:
              memory: "256Mi"
              cpu: "100m"
            limits:
              memory: "1Gi"
              cpu: "1000m"
          livenessProbe:
            httpGet:
              path: /xrpc/_health
              port: 3000
            initialDelaySeconds: 30
            periodSeconds: 10
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /xrpc/_health
              port: 3000
            initialDelaySeconds: 5
            periodSeconds: 5
            failureThreshold: 3
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            allowPrivilegeEscalation: false
---
apiVersion: v1
kind: Service
metadata:
  name: bspds
  namespace: bspds
spec:
  selector:
    app: bspds
  ports:
    - port: 80
      targetPort: 3000
      name: http
EOF
```
## 9. Configure Horizontal Pod Autoscaler
```bash
cat <<EOF | kubectl apply -f -
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: bspds
  namespace: bspds
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: bspds
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Pods
          value: 1
          periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
        - type: Percent
          value: 100
          periodSeconds: 15
        - type: Pods
          value: 4
          periodSeconds: 15
      selectPolicy: Max
EOF
```
## 10. Configure Pod Disruption Budget
```bash
cat <<EOF | kubectl apply -f -
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: bspds
  namespace: bspds
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: bspds
EOF
```
## 11. Configure TLS with cert-manager
```bash
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: your-email@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
      - http01:
          ingress:
            class: nginx
EOF
```
## 12. Configure Ingress
```bash
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: bspds
  namespace: bspds
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/proxy-read-timeout: "86400"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "86400"
    nginx.ingress.kubernetes.io/proxy-body-size: "100m"
    nginx.ingress.kubernetes.io/proxy-buffering: "off"
    nginx.ingress.kubernetes.io/websocket-services: "bspds"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - pds.example.com
      secretName: bspds-tls
  rules:
    - host: pds.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: bspds
                port:
                  number: 80
EOF
```
## 13. Configure Network Policies (Optional but Recommended)
```bash
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: bspds-network-policy
  namespace: bspds
spec:
  podSelector:
    matchLabels:
      app: bspds
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
      ports:
        - protocol: TCP
          port: 3000
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: bspds-db
      ports:
        - protocol: TCP
          port: 5432
    - to:
        - podSelector:
            matchLabels:
              app: bspds-minio
      ports:
        - protocol: TCP
          port: 9000
    - to:
        - podSelector:
            matchLabels:
              app: bspds-valkey
      ports:
        - protocol: TCP
          port: 6379
    - to:  # Allow DNS
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
    - to:  # Allow external HTTPS (for federation)
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - protocol: TCP
          port: 443
EOF
```
## 14. Deploy Prometheus Monitoring (Optional)
```bash
cat <<EOF | kubectl apply -f -
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: bspds
  namespace: bspds
  labels:
    release: prometheus
spec:
  selector:
    matchLabels:
      app: bspds
  endpoints:
    - port: http
      path: /metrics
      interval: 30s
EOF
```
---
## Verification
```bash
# Check all pods are running
kubectl get pods -n bspds
# Check services
kubectl get svc -n bspds
# Check ingress
kubectl get ingress -n bspds
# Check certificate
kubectl get certificate -n bspds
# Test health endpoint
curl -s https://pds.example.com/xrpc/_health | jq
# Test DID endpoint
curl -s https://pds.example.com/.well-known/atproto-did
```
---
## Maintenance
### View Logs
```bash
# All BSPDS pods
kubectl logs -l app=bspds -n bspds -f
# Specific pod
kubectl logs -f deployment/bspds -n bspds
```
### Scale Manually
```bash
kubectl scale deployment bspds --replicas=5 -n bspds
```
### Update BSPDS
```bash
# Build and push new image
docker build -t your-registry.com/bspds:v1.2.3 .
docker push your-registry.com/bspds:v1.2.3
# Update deployment
kubectl set image deployment/bspds bspds=your-registry.com/bspds:v1.2.3 -n bspds
# Watch rollout
kubectl rollout status deployment/bspds -n bspds
```
### Backup Database
```bash
# For CloudNativePG
kubectl cnpg backup bspds-db -n bspds
# For StatefulSet
kubectl exec -it bspds-db-0 -n bspds -- pg_dump -U bspds pds > backup-$(date +%Y%m%d).sql
```
### Run Migrations
If you have a migration Job defined, you can re-run it:
```bash
# Delete old job first (if exists)
kubectl delete job bspds-migrate -n bspds --ignore-not-found
# Re-apply the migration job from step 7
# Or simply restart the deployment - BSPDS runs migrations on startup
kubectl rollout restart deployment/bspds -n bspds
```
---
## Troubleshooting
### Pod Won't Start
```bash
kubectl describe pod -l app=bspds -n bspds
kubectl logs -l app=bspds -n bspds --previous
```
### Database Connection Issues
```bash
# Test connectivity from a debug pod
kubectl run debug --rm -it --restart=Never --image=postgres:18-alpine -- \
  psql "postgres://bspds:PASSWORD@bspds-db-rw:5432/pds" -c "SELECT 1"
```
### Certificate Issues
```bash
kubectl describe certificate bspds-tls -n bspds
kubectl describe certificaterequest -n bspds
kubectl logs -l app.kubernetes.io/name=cert-manager -n cert-manager
```
### View Resource Usage
```bash
kubectl top pods -n bspds
kubectl top nodes
```
