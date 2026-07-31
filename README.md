# HE Employee Voting

A small OpenFHE BFV demo for employee voting with choices A, B, and C.

- The prepared employee ID is visible application metadata.
- Each choice is encoded as three values: A=`1,0,0`, B=`0,1,0`,
  C=`0,0,1`.
- Each row is encrypted separately into three ciphertexts.
- The server performs three homomorphic `EvalAdd` operations per accepted row.
- Ballot ciphertexts and encrypted running totals are retained on disk.
- Only the final aggregate A/B/C totals are decrypted.
- Repeated submissions are counted. There is no duplicate-vote check.

## Code layout

```text
python/he_voting/       OpenFHE context, encryption, EvalAdd, decryption only
app/                    API, SQLite metadata, UI, static files
scripts/                generation, setup, client, benchmark, decryption
k8s/                    app deployment and persistent runtime storage
```

The core HE calculation is
`python/he_voting/openfhe_backend.py`. The application calls it from
`app/voting_service.py`.

## Install on the server

```bash
cd /root/he_voting
python3 -m venv .venv
.venv/bin/pip install -r requirements-openfhe.txt
```

The selected package is pinned in `requirements-openfhe.txt`.

## Prepare a local election

```bash
.venv/bin/python scripts/generate_data.py \
  --out-dir generated \
  --employees 16 \
  --votes 10

.venv/bin/python scripts/setup_election.py \
  --employees generated/employees.csv \
  --runtime-dir runtime \
  --trustee-dir trustee
```

Setup is fresh-only by default. It refuses non-empty runtime and trustee
directories so the context/key pair cannot be replaced accidentally.

Start the app locally:

```bash
HE_VOTING_RUNTIME=/root/he_voting/runtime \
PYTHONPATH=/root/he_voting:/root/he_voting/python \
.venv/bin/uvicorn app.api:create_app \
  --factory \
  --host 0.0.0.0 \
  --port 8000 \
  --workers 1
```

Open `/vote`, `/admin`, `/storage`, or `/result`. The Storage page lists
retained ciphertext files with their size, SHA-256, and a short opaque Base64
preview. The demo vote page encrypts the selected choice in the app process
because a Python OpenFHE wheel cannot run in a normal browser. The
production-style `/election/vote` endpoint accepts ciphertexts created by
`scripts/client.py`.

## Submit prepared rows separately

```bash
.venv/bin/python scripts/submit_csv.py \
  --votes generated/votes.csv \
  --public-dir runtime/public \
  --api-url http://127.0.0.1:8000
```

Or submit one row:

```bash
.venv/bin/python scripts/client.py \
  --employee-id 100001 \
  --choice A \
  --public-dir runtime/public \
  --api-url http://127.0.0.1:8000
```

## Decrypt only the final aggregate

```bash
.venv/bin/python scripts/decrypt_result.py \
  --runtime-dir runtime \
  --trustee-dir trustee \
  --publish
```

## Kubernetes UI demo

See [UI_K8S_DEMO.md](UI_K8S_DEMO.md). The app runs as one replica and mounts a
persistent host directory. Election setup and trustee decryption stay outside
Kubernetes.

`election.json`, `/health`, and the Progress page expose the same short
`context_id`. Startup also checks the full SHA-256 values of the context and
public key against the election manifest. The trustee key is stored separately
with its paired context fingerprint.

## Test

```bash
.venv/bin/pytest -q
```

Contract tests use a fake OpenFHE module. Native end-to-end tests run when the
server has the `openfhe` Python package installed.
