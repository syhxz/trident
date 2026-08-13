# Kubernetes Deployment

For environments with an existing Kubernetes cluster where you want to manage Trident
using standard Deployment/Service resources.

## Prerequisites

- A `trident:latest` image has been built (`docker build -t trident:latest .`) and pushed
  to a registry accessible by the cluster, or locally loaded (kind/minikube `load`).
- Backend PostgreSQL nodes (Writer/Reader/Analytics) already exist. This repository does
  not provide deployment manifests for the backend databases.

## Deployment Steps

```sh
kubectl apply -f deploy/k8s/00-namespace.yaml

# Generate the Secret with real passwords (do not commit real passwords to version control)
kubectl create secret generic trident-config \
  --namespace trident \
  --from-file=config.yaml=./config.yaml \
  --dry-run=client -o yaml | kubectl apply -f -

# If your config.yaml uses ${ENV_VAR} placeholders for passwords (recommended),
# create a separate Secret for the password environment variables:
kubectl create secret generic trident-passwords \
  --namespace trident \
  --from-literal=TRIDENT_PRIMARY_PASSWORD=your_primary_pw \
  --from-literal=TRIDENT_READER1_PASSWORD=your_reader1_pw \
  --from-literal=TRIDENT_READER2_PASSWORD=your_reader2_pw \
  --from-literal=TRIDENT_ANALYTICS1_PASSWORD=your_analytics1_pw \
  --dry-run=client -o yaml | kubectl apply -f -
# Then reference it in 20-deployment.yaml via envFrom or individual env entries.
# If your config uses plaintext passwords, this step is not needed.

kubectl apply -f deploy/k8s/20-deployment.yaml
kubectl apply -f deploy/k8s/30-service.yaml

kubectl -n trident get pods -w
kubectl -n trident logs -f deploy/trident
```

## Known Limitations (read first)

1. **`replicas > 1` is the multi-instance scenario discussed in DEPLOYMENT.md section 8**:
   `ConsistencyLevel::Global` is not correct across pods. When running multiple replicas,
   set `routing.default_consistency` to `session` or `eventual`.
2. **Probes**: `readinessProbe` is configured as `httpGet /healthz` (requires
   `admin.enabled: true` and `admin.listen_addr` bound to `0.0.0.0` in
   `10-config-secret.yaml`; see comments in that file). `livenessProbe` uses a TCP probe
   (an unhealthy health endpoint does not mean the process should be killed and restarted —
   it should only affect traffic routing, so liveness intentionally does not reuse the same
   logic as readiness). `/metrics`/`/healthz` listen only on a pod-internal port with no
   Service exposing them externally, consistent with their no-authentication design.
3. **CANCEL request session stickiness**: `30-service.yaml` configures
   `sessionAffinity: ClientIP` to reduce (but not eliminate) the probability of CANCEL
   requests being routed to a different pod and silently failing in multi-replica setups.
   See DEPLOYMENT.md section 8.3.
4. **Password storage**: `NodeConfig.password` now supports `${ENV_VAR}` placeholders or
   omission with `.pgpass` lookup (see DEPLOYMENT.md section 2). You can split
   `10-config-secret.yaml` into a ConfigMap (non-sensitive `proxy`/`routing`/`pool`/
   `health`/`logging`) plus a small Secret containing only passwords (injected as
   environment variables, using `${ENV_VAR}` placeholders). An example is shown in the
   comments at the top of `10-config-secret.yaml`. The current file demonstrates the
   simpler approach of storing the entire config as a Secret; both methods work.
