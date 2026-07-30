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
python/he_voting/openfhe_backend.py
                             Complete OpenFHE BFV implementation
python/he_voting/api.py      FastAPI endpoints
python/he_voting/service.py  Ordered processing, SQLite, receipts, hash chain
scripts/generate_data.py     Roster and two-column vote generator
scripts/setup_election.py    Key, encrypted flag, tally, and database setup
scripts/client.py            Encrypt and submit one vote
scripts/submit_csv.py        Submit generated rows one at a time
scripts/decrypt_result.py    Trustee-side aggregate-only decryption
tests/                       Duplicate, API, concurrency, and privacy tests
```

The HE context and evaluation keys are loaded once per Python process. Every
row still receives three fresh randomized ciphertexts and is processed
synchronously.

## 1. Install OpenFHE Python

Create the environment and install the official bindings:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-openfhe.txt
```

The project pins the newest official server wheel,
`openfhe==1.5.1.0.24.4`, for Ubuntu 24.04 and Python 3.12+. On a server where
the binding must instead be compiled against the local OpenFHE install, build
[openfhe-python](https://github.com/openfheorg/openfhe-python) with:

```text
-DCMAKE_PREFIX_PATH=/usr/local/lib/OpenFHE
```

The OpenFHE C++ library and Python wrapper versions must match.

For a source build against the server installation:

```bash
git clone \
  --branch v1.5.1.0 \
  --depth 1 \
  https://github.com/openfheorg/openfhe-python.git \
  ../openfhe-python
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install "pybind11[global]"

OPENFHE_PYTHON_SITE="$(
  .venv/bin/python -c \
    'import sysconfig; print(sysconfig.get_paths()["purelib"])'
)"

cmake \
  -S ../openfhe-python \
  -B ../openfhe-python/build \
  -DCMAKE_PREFIX_PATH=/usr/local/lib/OpenFHE \
  -DPYTHON_EXECUTABLE_PATH="$PWD/.venv/bin/python" \
  -DCMAKE_INSTALL_PREFIX="$OPENFHE_PYTHON_SITE"

cmake --build ../openfhe-python/build --parallel 2
cmake --install ../openfhe-python/build
```

Verify the binding:

```bash
.venv/bin/python -c "import openfhe; print(openfhe.__file__)"
```

Create a fresh election runtime after migrating. Do not continue an old runtime
created with a different OpenFHE library/wrapper version.

## 2. Generate the duplicate fixture

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

## 3. Initialize an election

```bash
.venv/bin/python \
  scripts/setup_election.py \
  --roster generated/roster.csv \
  --runtime-dir runtime \
  --trustee-dir runtime_trustee
```

The API runtime does not contain the secret key. It is written only to
`runtime_trustee`.

## 4. Run the API

```bash
export PYTHONPATH="$PWD/python"
export HE_VOTING_RUNTIME="$PWD/runtime"

.venv/bin/uvicorn \
  he_voting.api:create_app \
  --factory \
  --host 127.0.0.1 \
  --port 8000 \
  --workers 1
```

Exactly one API worker is required by this MVP so encrypted flag and tally
updates remain ordered.

## 5. Submit rows one at a time

```bash
.venv/bin/python \
  scripts/submit_csv.py \
  --votes generated/votes.csv \
  --roster generated/roster.csv \
  --public-dir runtime/public \
  --api-url http://127.0.0.1:8000
```

Or submit one vote:

```bash
.venv/bin/python \
  scripts/client.py \
  --employee-id 100001 \
  --choice A \
  --roster generated/roster.csv \
  --public-dir runtime/public
```

## 6. Trustee decrypts only the total

```bash
.venv/bin/python \
  scripts/decrypt_result.py \
  --runtime-dir runtime \
  --trustee-dir runtime_trustee \
  --publish
```

For the four-row fixture, the expected result is:

```json
{"A": 1, "B": 1, "C": 1}
```

No flag or individual-ballot decryption command exists. The trustee decryption
operation accepts only the directory containing the final A, B, and C aggregate
ciphertexts.

## 7. Run tests

```bash
.venv/bin/pytest
```

## Core HE calculation

The complete encrypted voting calculation is in:

```text
python/he_voting/openfhe_backend.py
```

`OpenFHEBackend.evaluate()` performs one subtraction, three multiplications,
and four additions. The service never decrypts a ballot, flag, or running
tally.

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
  --trustee-dir trustee_benchmark_100
```

Then run the local sequential benchmark:

```bash
.venv/bin/python scripts/benchmark_votes.py \
  --votes benchmark_data/votes_100_dup10/votes.csv \
  --roster benchmark_data/votes_100_dup10/roster.csv \
  --runtime-dir runtime_benchmark_100 \
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
