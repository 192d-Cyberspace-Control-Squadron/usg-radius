# Kubernetes Deployment for usg-radius HA Cluster

This directory contains Kubernetes manifests for deploying a High Availability RADIUS cluster.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Kubernetes Cluster                 │
│                                                      │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐   │
│  │  RADIUS    │  │  RADIUS    │  │  RADIUS    │   │
│  │  Pod 1     │  │  Pod 2     │  │  Pod 3     │   │
│  └──────┬─────┘  └──────┬─────┘  └──────┬─────┘   │
│         │               │               │          │
│         └───────────────┼───────────────┘          │
│                         │                          │
│                  ┌──────▼──────┐                   │
│                  │   Valkey    │                   │
│                  │ StatefulSet │                   │
│                  └─────────────┘                   │
└─────────────────────────────────────────────────────┘
```

## Prerequisites

- Kubernetes cluster (1.21+)
- `kubectl` configured to access your cluster
- Storage provisioner for PersistentVolumeClaims
- (Optional) Prometheus Operator for monitoring

## Quick Start

### 1. Build and Push Docker Image

```bash
# Build the image
docker build -t your-registry/usg-radius:latest .

# Push to your registry
docker push your-registry/usg-radius:latest

# Update radius-server.yaml with your image
sed -i 's|usg-radius:latest|your-registry/usg-radius:latest|' radius-server.yaml
```

### 2. Deploy to Kubernetes

```bash
# Create namespace
kubectl apply -f namespace.yaml

# Deploy Valkey (state backend)
kubectl apply -f valkey.yaml

# Wait for Valkey to be ready
kubectl wait --for=condition=ready pod -l app=valkey -n radius --timeout=120s

# Deploy RADIUS servers
kubectl apply -f radius-server.yaml

# Wait for RADIUS pods to be ready
kubectl wait --for=condition=ready pod -l app=radius-server -n radius --timeout=120s
```

### 3. Verify Deployment

```bash
# Check all resources
kubectl get all -n radius

# Check pod status
kubectl get pods -n radius

# View logs
kubectl logs -f deployment/radius-server -n radius

# Test health endpoint
kubectl port-forward svc/radius-server 2812:2812 -n radius
curl http://localhost:2812/health

# View metrics
kubectl port-forward svc/radius-server 3812:3812 -n radius
curl http://localhost:3812/metrics
```

## Configuration

### Environment Variables

Edit `radius-config` ConfigMap in `radius-server.yaml`:

```yaml
data:
  RADIUS_PORT: "1812"
  VALKEY_URL: "redis://valkey:6379"
  RUST_LOG: "radius_server=debug,info"
```

### Secrets

Update `radius-secret` Secret with your RADIUS shared secret:

```bash
kubectl create secret generic radius-secret \
  --from-literal=radius-secret='your_strong_secret_here' \
  -n radius --dry-run=client -o yaml | kubectl apply -f -
```

### Resource Limits

Adjust resources in `radius-server.yaml`:

```yaml
resources:
  requests:
    cpu: 100m      # Increase for high load
    memory: 128Mi  # Increase for many sessions
  limits:
    cpu: 1000m
    memory: 512Mi
```

### Auto-Scaling

The HPA (HorizontalPodAutoscaler) is configured to scale based on CPU/memory:

- Min replicas: 3
- Max replicas: 10
- Target CPU: 70%
- Target Memory: 80%

Adjust in `radius-server.yaml`:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
spec:
  minReplicas: 3
  maxReplicas: 10
```

## Monitoring

### Prometheus Integration

If you have Prometheus Operator installed:

```bash
kubectl apply -f monitoring/servicemonitor.yaml
```

The pods are annotated for automatic discovery:

```yaml
annotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "3812"
  prometheus.io/path: "/metrics"
```

### Grafana Dashboards

Import the provided Grafana dashboard:

```bash
kubectl apply -f monitoring/grafana-dashboard.yaml
```

## Load Balancing

### Internal Load Balancer

For internal cluster access, the Service uses `ClusterIP`:

```yaml
apiVersion: v1
kind: Service
spec:
  type: ClusterIP  # Internal only
```

### External Load Balancer

For external access (cloud provider):

```yaml
apiVersion: v1
kind: Service
spec:
  type: LoadBalancer  # Cloud LB
```

### NodePort

For on-premise deployments:

```yaml
apiVersion: v1
kind: Service
spec:
  type: NodePort
  ports:
    - port: 1812
      nodePort: 31812  # Accessible on all nodes
```

## High Availability

### Pod Disruption Budget

Ensure minimum availability during updates:

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: radius-server-pdb
  namespace: radius
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: radius-server
```

### Anti-Affinity

Spread pods across nodes:

```yaml
spec:
  template:
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchLabels:
                    app: radius-server
                topologyKey: kubernetes.io/hostname
```

## Persistence

### Valkey Data

Valkey uses a StatefulSet with PersistentVolumeClaim:

```yaml
volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi  # Adjust based on session volume
```

### Backup Strategy

Recommended: Use Valkey AOF + scheduled backups:

```bash
# Create CronJob for backups
kubectl apply -f backup/valkey-backup-cronjob.yaml
```

## Security

### Network Policies

Restrict network access:

```bash
kubectl apply -f security/networkpolicy.yaml
```

Example NetworkPolicy:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: radius-server-netpol
  namespace: radius
spec:
  podSelector:
    matchLabels:
      app: radius-server
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: radius
      ports:
        - protocol: UDP
          port: 1812
        - protocol: TCP
          port: 2812
        - protocol: TCP
          port: 3812
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: valkey
      ports:
        - protocol: TCP
          port: 6379
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 53
        - protocol: UDP
          port: 53
```

### Pod Security Standards

Apply Pod Security Standards:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: radius
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

## Troubleshooting

### Pods Not Starting

```bash
# Check pod status
kubectl get pods -n radius

# View pod events
kubectl describe pod <pod-name> -n radius

# Check logs
kubectl logs <pod-name> -n radius

# Check Valkey connectivity
kubectl exec -it <radius-pod> -n radius -- sh
ping valkey
```

### Health Check Failures

```bash
# Test health endpoint locally
kubectl exec -it <radius-pod> -n radius -- curl http://localhost:2812/health

# Check backend connectivity
kubectl exec -it <radius-pod> -n radius -- sh
curl http://localhost:2812/health | jq .backend
```

### Performance Issues

```bash
# Check resource usage
kubectl top pods -n radius

# View metrics
kubectl port-forward svc/radius-server 3812:3812 -n radius
curl http://localhost:3812/metrics

# Check HPA status
kubectl get hpa -n radius
kubectl describe hpa radius-server -n radius
```

## Upgrading

### Rolling Update

```bash
# Update image
kubectl set image deployment/radius-server \
  radius-server=your-registry/usg-radius:v2 \
  -n radius

# Watch rollout
kubectl rollout status deployment/radius-server -n radius

# Rollback if needed
kubectl rollout undo deployment/radius-server -n radius
```

### Blue-Green Deployment

1. Deploy new version with different label
2. Test new version
3. Switch service selector
4. Remove old deployment

## Cleanup

```bash
# Delete all resources
kubectl delete -f .

# Or delete namespace (removes everything)
kubectl delete namespace radius
```

## Production Checklist

- [ ] Custom container image built and pushed
- [ ] Secrets updated with strong passwords
- [ ] Resource limits tuned for workload
- [ ] PersistentVolume storage class configured
- [ ] NetworkPolicies applied
- [ ] Pod Security Standards enforced
- [ ] Prometheus monitoring configured
- [ ] Grafana dashboards imported
- [ ] Backup CronJob configured
- [ ] Load balancer configured
- [ ] DNS entries created
- [ ] TLS certificates configured (if needed)
- [ ] Horizontal Pod Autoscaler tested
- [ ] Pod Disruption Budget created
- [ ] Anti-affinity rules applied
- [ ] Tested failover scenarios
- [ ] Documentation updated

## Additional Resources

- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/configuration/overview/)
- [StatefulSet Documentation](https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/)
- [HPA Documentation](https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/)
- [Prometheus Operator](https://github.com/prometheus-operator/prometheus-operator)
