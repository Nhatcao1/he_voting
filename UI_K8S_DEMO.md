# UI and Kubernetes demo

Only the web application runs in Kubernetes. Data generation, election setup,
benchmarking, and aggregate decryption remain explicit Python commands on the
server.

## Prepare one election

Run these commands once. Do not use `--force` on an election you want to keep.

```bash
cd /root/he_voting

.venv/bin/python scripts/generate_data.py \
  --out-dir generated_k8s \
  --employees 16 \
  --votes 10

mkdir -p /root/he_voting/runtime_k8s

.venv/bin/python scripts/setup_election.py \
  --employees generated_k8s/employees.csv \
  --runtime-dir /root/he_voting/runtime_k8s \
  --trustee-dir /root/he_voting/trustee_k8s

sha256sum /root/he_voting/runtime_k8s/public/crypto_context.bin
```

The setup output includes `context_id`. The same short ID appears at
`/health` and on the Progress page.

## Build and deploy the app

```bash
cd /root/he_voting
docker build -t he-voting:demo .
docker save he-voting:demo | sudo k3s ctr images import -
kubectl apply -f k8s/storage.yaml
kubectl apply -f k8s/app.yaml
kubectl rollout status deployment/he-voting
```

For Kubernetes distributions other than k3s, load `he-voting:demo` into the
cluster's container runtime or push it to a registry before applying the
manifests.

Open:

```text
http://SERVER_IP:30880/vote
http://SERVER_IP:30880/admin
http://SERVER_IP:30880/storage
http://SERVER_IP:30880/result
```

## Context survival check

```bash
curl -s http://127.0.0.1:30880/health
kubectl delete pod -l app=he-voting
kubectl rollout status deployment/he-voting
curl -s http://127.0.0.1:30880/health
```

`context_id` must be identical before and after the restart. The PV uses the
host directory `/root/he_voting/runtime_k8s` with reclaim policy `Retain`, so
the serialized context, public key, encrypted tallies, ballot ciphertexts, and
SQLite metadata are not part of the pod filesystem.

The paired trustee key remains outside Kubernetes at
`/root/he_voting/trustee_k8s/secret_key.bin`. Replacing either the runtime
context or that key breaks the pair. This hostPath layout is intended for a
single-node demo cluster.

## Publish the final aggregate

```bash
cd /root/he_voting
.venv/bin/python scripts/decrypt_result.py \
  --runtime-dir /root/he_voting/runtime_k8s \
  --trustee-dir /root/he_voting/trustee_k8s \
  --publish
```

Only the aggregate A/B/C totals are decrypted. Refresh `/result` to display
the published values.
