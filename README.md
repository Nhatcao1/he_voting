# HE Employee A/B/C Voting MVP

This project exposes a web API for one-choice employee voting while keeping the
choice, `has_voted` state, and A/B/C tally encrypted with OpenFHE BFV.

The generated vote file stays intentionally small:

```csv
employee_id,choice
100001,A
100002,B
100003,C
100001,B
```

The final row is a deliberate duplicate. Its encrypted choice is processed but
adds zero to the tally.

## Privacy boundary

The employee ID is used only by the local voter client. The local roster maps it
to a random per-election voter token. The API receives:

```text
random voter token
encrypted [A, B, C] choice
```

The random token lets the server locate one encrypted `has_voted` ciphertext
without learning the employee ID. The server can recognize that the same token
was submitted again, but it cannot map that token to an employee or decrypt the
choice, flag, or tally.

The OpenFHE computation is:

```text
can_vote      = Enc([1,1,1]) - encrypted_has_voted
accepted_vote = can_vote * encrypted_choice
new_tally     = encrypted_tally + accepted_vote
new_flag      = encrypted_has_voted + can_vote
```

The first request changes the encrypted flag from `[0,0,0]` to `[1,1,1]`.
Every duplicate therefore contributes `[0,0,0]`.

## Components

```text
cpp/                         OpenFHE BFV evaluator and command-line runtime
python/he_voting/api.py      FastAPI endpoints
python/he_voting/service.py  Ordered processing, SQLite, receipts, hash chain
scripts/generate_data.py     Roster and two-column vote generator
scripts/setup_election.py    Key, encrypted flag, tally, and database setup
scripts/client.py            Encrypt and submit one vote
scripts/submit_csv.py        Submit generated rows one at a time
scripts/decrypt_result.py    Trustee-side aggregate-only decryption
tests/                       Duplicate, API, concurrency, and privacy tests
```

## 1. Build OpenFHE evaluator

From the Viettel workspace:

```bash
cmake \
  -S he_voting_count \
  -B he_voting_count/build \
  -DOpenFHE_DIR="$PWD/openfhe-install/lib/OpenFHE" \
  -DCMAKE_BUILD_TYPE=Release

cmake --build he_voting_count/build --parallel 2
```

## 2. Create Python environment

```bash
python3 -m venv he_voting_count/.venv
he_voting_count/.venv/bin/pip install -r he_voting_count/requirements.txt
```

## 3. Generate the duplicate fixture

```bash
he_voting_count/.venv/bin/python \
  he_voting_count/scripts/generate_data.py \
  --out-dir he_voting_count/generated \
  --employees 16 \
  --votes 4 \
  --duplicates 1
```

The vote CSV contains only `employee_id,choice`. The roster contains the local
employee-to-token mapping and must stay on the client side.

## 4. Initialize an election

```bash
PYTHONPATH=he_voting_count/python \
he_voting_count/.venv/bin/python \
  he_voting_count/scripts/setup_election.py \
  --roster he_voting_count/generated/roster.csv \
  --runtime-dir he_voting_count/runtime \
  --trustee-dir he_voting_count/runtime_trustee \
  --crypto-bin he_voting_count/build/he_voting_crypto
```

The API runtime does not contain the secret key. It is written only to
`runtime_trustee`.

## 5. Run the API

```bash
export PYTHONPATH="$PWD/he_voting_count/python"
export HE_VOTING_RUNTIME="$PWD/he_voting_count/runtime"
export HE_VOTING_CRYPTO_BIN="$PWD/he_voting_count/build/he_voting_crypto"
export HE_EVALUATOR="openfhe"

he_voting_count/.venv/bin/uvicorn \
  he_voting.api:create_app \
  --factory \
  --host 127.0.0.1 \
  --port 8000 \
  --workers 1
```

Exactly one API worker is required by this MVP so encrypted flag and tally
updates remain ordered.

## 6. Submit rows one at a time

```bash
he_voting_count/.venv/bin/python \
  he_voting_count/scripts/submit_csv.py \
  --votes he_voting_count/generated/votes.csv \
  --roster he_voting_count/generated/roster.csv \
  --public-dir he_voting_count/runtime/public \
  --crypto-bin he_voting_count/build/he_voting_crypto \
  --api-url http://127.0.0.1:8000
```

Or submit one vote:

```bash
he_voting_count/.venv/bin/python \
  he_voting_count/scripts/client.py \
  --employee-id 100001 \
  --choice A \
  --roster he_voting_count/generated/roster.csv \
  --public-dir he_voting_count/runtime/public \
  --crypto-bin he_voting_count/build/he_voting_crypto
```

## 7. Trustee decrypts only the total

```bash
he_voting_count/.venv/bin/python \
  he_voting_count/scripts/decrypt_result.py \
  --runtime-dir he_voting_count/runtime \
  --trustee-dir he_voting_count/runtime_trustee \
  --crypto-bin he_voting_count/build/he_voting_crypto \
  --publish
```

For the four-row fixture, the expected result is:

```json
{"A": 1, "B": 1, "C": 1}
```

The debug-only native `decrypt-flag` command exists for automated testing. It
is not exposed by the API.

## 8. Run tests

```bash
he_voting_count/.venv/bin/pytest he_voting_count
```

## HEIR option

The evaluator interface accepts `HE_EVALUATOR=heir-openfhe`, but that choice
fails closed until a reviewed HEIR-generated OpenFHE kernel is compiled into
the native binary. OpenFHE is the implemented evaluator. HEIR would generate
the same fixed `EvaluateVote` arithmetic and still use OpenFHE for ciphertexts,
keys, serialization, and execution.

## Current limitations

- The MVP uses one trustee secret key, not threshold key shares yet.
- The supplied client is trusted to encrypt only A, B, or C.
- The ballot server can see repeated random voter tokens, but cannot map them to
  employee IDs unless it also obtains the private local roster.
- The plaintext modulus is `65537`, so an election must stay below that count.
- Each employee has a separate encrypted flag ciphertext; benchmark storage
  before creating a very large real roster.

