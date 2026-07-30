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
three separate encrypted scalar choice bits: A, B, C
```

The random token lets the server locate one encrypted `has_voted` ciphertext
without learning the employee ID. The server can recognize that the same token
was submitted again, but it cannot map that token to an employee or decrypt the
choice, flag, or tally.

The OpenFHE computation is:

```text
can_vote = Enc(1) - encrypted_has_voted

accepted_A = can_vote * encrypted_choice_A
accepted_B = can_vote * encrypted_choice_B
accepted_C = can_vote * encrypted_choice_C

new_tally_A = encrypted_tally_A + accepted_A
new_tally_B = encrypted_tally_B + accepted_B
new_tally_C = encrypted_tally_C + accepted_C

new_flag = encrypted_has_voted + can_vote
```

All seven values above are separate BFV coefficient-encoded scalar
ciphertexts. No choice or tally uses SIMD packing. The first request changes
the encrypted flag from `Enc(0)` to `Enc(1)`. Every duplicate therefore
contributes encrypted zero to all three counters.

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

From the cloned repository root:

```bash
cmake \
  -S . \
  -B build \
  -DOpenFHE_DIR=/usr/local/lib/OpenFHE \
  -DCMAKE_BUILD_TYPE=Release

cmake --build build --parallel 2
```

## 2. Create Python environment

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## 3. Generate the duplicate fixture

```bash
.venv/bin/python \
  scripts/generate_data.py \
  --out-dir generated \
  --employees 16 \
  --votes 4 \
  --duplicates 1
```

The vote CSV contains only `employee_id,choice`. The roster contains the local
employee-to-token mapping and must stay on the client side.

## 4. Initialize an election

```bash
.venv/bin/python \
  scripts/setup_election.py \
  --roster generated/roster.csv \
  --runtime-dir runtime \
  --trustee-dir runtime_trustee \
  --crypto-bin build/he_voting_crypto
```

The API runtime does not contain the secret key. It is written only to
`runtime_trustee`.

## 5. Run the API

```bash
export PYTHONPATH="$PWD/python"
export HE_VOTING_RUNTIME="$PWD/runtime"
export HE_VOTING_CRYPTO_BIN="$PWD/build/he_voting_crypto"
export HE_EVALUATOR="openfhe"

.venv/bin/uvicorn \
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
.venv/bin/python \
  scripts/submit_csv.py \
  --votes generated/votes.csv \
  --roster generated/roster.csv \
  --public-dir runtime/public \
  --crypto-bin build/he_voting_crypto \
  --api-url http://127.0.0.1:8000
```

Or submit one vote:

```bash
.venv/bin/python \
  scripts/client.py \
  --employee-id 100001 \
  --choice A \
  --roster generated/roster.csv \
  --public-dir runtime/public \
  --crypto-bin build/he_voting_crypto
```

## 7. Trustee decrypts only the total

```bash
.venv/bin/python \
  scripts/decrypt_result.py \
  --runtime-dir runtime \
  --trustee-dir runtime_trustee \
  --crypto-bin build/he_voting_crypto \
  --publish
```

For the four-row fixture, the expected result is:

```json
{"A": 1, "B": 1, "C": 1}
```

No flag or individual-ballot decryption command exists. The native decryption
command accepts only the directory containing the final A, B, and C aggregate
ciphertexts.

## 8. Run tests

```bash
.venv/bin/pytest
```

## HEIR option

The evaluator interface accepts `HE_EVALUATOR=heir-openfhe`, but that choice
fails closed until a reviewed HEIR-generated OpenFHE kernel is compiled into
the native binary. OpenFHE is the implemented evaluator. HEIR would generate
the same fixed `EvaluateVote` arithmetic and still use OpenFHE for ciphertexts,
keys, serialization, and execution.

## Simple timing benchmark

Generate the standard 100, 1,000, and 10,000-vote fixtures with 10% duplicates:

```bash
.venv/bin/python scripts/generate_benchmark_data.py \
  --out-dir benchmark_data \
  --duplicate-percent 10
```

Use `--duplicate-percent 20` for 20% duplicates.

The generated directories are:

```text
benchmark_data/votes_100_dup10
benchmark_data/votes_1000_dup10
benchmark_data/votes_10000_dup10
```

Prepare a fresh local election for the quota being measured. Example for 100
votes:

```bash
.venv/bin/python scripts/setup_election.py \
  --roster benchmark_data/votes_100_dup10/roster.csv \
  --runtime-dir runtime_benchmark_100 \
  --trustee-dir trustee_benchmark_100 \
  --crypto-bin build/he_voting_crypto
```

Then run the local sequential benchmark:

```bash
.venv/bin/python scripts/benchmark_votes.py \
  --votes benchmark_data/votes_100_dup10/votes.csv \
  --roster benchmark_data/votes_100_dup10/roster.csv \
  --runtime-dir runtime_benchmark_100 \
  --crypto-bin build/he_voting_crypto \
  --out-dir benchmark_results/100_dup10
```

Change `100` to `1000` or `10000` for the larger cases, using a fresh runtime
for each case.

The benchmark writes:

```text
per_vote_times.csv   one row per separately encrypted and processed vote
summary.json         total time, votes/second, average, median, and p95
```

Timing is split into fresh encryption, encrypted vote processing, and complete
end-to-end time. The script waits for each row to finish before starting the
next row. It does not start an HTTP server or process votes in the background.

The 10,000-vote case is intentionally heavy: each vote contains three BFV
ciphertexts and each eligible employee has an encrypted flag. Reserve
substantial disk space and run 100 then 1,000 first before starting 10,000.

## Current limitations

- The MVP uses one trustee secret key, not threshold key shares yet.
- The supplied client is trusted to encrypt only A, B, or C.
- Every CSV row is independently encrypted and submitted as its own API
  request; rows are never combined into an input array.
- Each choice creates three separate scalar ciphertexts, and the server stores
  three separate scalar tally ciphertexts. No SIMD packing is used.
- The ballot server can see repeated random voter tokens, but cannot map them to
  employee IDs unless it also obtains the private local roster.
- The plaintext modulus is `65537`, so an election must stay below that count.
- Each employee has a separate encrypted flag ciphertext; benchmark storage
  before creating a very large real roster.
