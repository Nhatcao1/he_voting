# HE Employee A/B/C Voting MVP

This project exposes a web API for one-choice employee voting. Participation is
tracked by a token hash in SQLite, while each A/B/C choice and the running
A/B/C tally remain encrypted with OpenFHE BFV.

The generated vote file stays intentionally small:

```csv
employee_id,choice
100001,A
100002,B
100003,C
100004,A
```

Every row is independently encrypted, retained, and added to the encrypted
tally.

## Privacy boundary

The employee ID is used by the local voter client. The local roster maps it to
a per-election voter token. The API receives:

```text
per-election voter token
three separate encrypted scalar choice bits: A, B, C
```

The server hashes the token and records that hash with the ballot metadata. An
administrator who also has the restricted roster can determine whether an
employee submitted, but the employee's A/B/C choice remains encrypted. This
MVP does not enforce one submission per employee.

The OpenFHE computation is:

```text
new_tally_A = encrypted_tally_A + encrypted_choice_A
new_tally_B = encrypted_tally_B + encrypted_choice_B
new_tally_C = encrypted_tally_C + encrypted_choice_C
```

All six values above are separate BFV coefficient-encoded scalar ciphertexts.
No choice or tally uses SIMD packing. Every eligible submission reaches these
three HE additions.

## Components

```text
python/he_voting/openfhe_backend.py
                             Complete OpenFHE BFV implementation
python/he_voting/api.py      FastAPI endpoints
python/he_voting/service.py  Eligibility, participation, tally updates, receipts
scripts/generate_data.py     Roster and two-column vote generator
scripts/setup_election.py    Key, encrypted tally, and database setup
scripts/client.py            Encrypt and submit one vote
scripts/submit_csv.py        Submit generated rows one at a time
scripts/decrypt_result.py    Trustee-side aggregate-only decryption
tests/                       Tally, API, concurrency, and privacy tests
```

The HE context and public key are loaded once per Python process. Multiplication
evaluation keys are unnecessary because tallying uses ciphertext addition only.
Every row still receives three fresh randomized ciphertexts and is submitted
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
created with a different OpenFHE library/wrapper version or with the previous
encrypted-flag design. The service rejects legacy flag runtimes to prevent old
participants from being counted again.

## 2. Generate the test fixture

```bash
.venv/bin/python \
  scripts/generate_data.py \
  --out-dir generated \
  --employees 16 \
  --votes 4
```

The vote CSV contains only `employee_id,choice`. The roster contains the
restricted employee-to-token mapping used for setup, test submission, and the
authorized participation report. It must not be exposed with public results.

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

Exactly one API worker is required by this MVP so participation claims and
encrypted tally file updates remain ordered.

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
{"A": 2, "B": 1, "C": 1}
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

`OpenFHEBackend.evaluate()` performs exactly three ciphertext additions. The
service never decrypts a ballot or running tally.

## Simple timing benchmark

Generate the standard 100, 1,000, and 10,000-vote fixtures:

```bash
.venv/bin/python scripts/generate_benchmark_data.py \
  --out-dir benchmark_data
```

The generated directories are:

```text
benchmark_data/votes_100
benchmark_data/votes_1000
benchmark_data/votes_10000
```

Prepare a fresh local election for the quota being measured. Example for 100
votes:

```bash
.venv/bin/python scripts/setup_election.py \
  --roster benchmark_data/votes_100/roster.csv \
  --runtime-dir runtime_benchmark_100 \
  --trustee-dir trustee_benchmark_100
```

Then run the local sequential benchmark:

```bash
.venv/bin/python scripts/benchmark_votes.py \
  --votes benchmark_data/votes_100/votes.csv \
  --roster benchmark_data/votes_100/roster.csv \
  --runtime-dir runtime_benchmark_100 \
  --trustee-dir trustee_benchmark_100 \
  --out-dir benchmark_results/100
```

Change `100` to `1000` or `10000` for the larger cases, using a fresh runtime
for each case.

The benchmark writes a client-facing evidence bundle:

```text
input_votes.csv              exact generated input
per_vote_times.csv           per-row encryption/server/end-to-end timing
vote_evidence.csv            input, one-hot encoding, status, ciphertext metadata
participation.csv            employee submitted/not-submitted status, no choice
ciphertexts/ballots/         three retained ciphertext files per submitted row
ciphertexts/final_tally/     final encrypted A/B/C tally files
expected_result.json         generated expected A/B/C totals
decrypted_result.json        aggregate-only trustee output
final_result.csv             expected vs decrypted totals and ciphertext previews
checksums.sha256             integrity hashes for every retained ciphertext
summary.json                 overall timing and result comparison
```

Quickly inspect the client evidence:

```bash
sed -n '1,6p' benchmark_results/100/vote_evidence.csv
sed -n '1,6p' benchmark_results/100/participation.csv
sed -n '1,6p' benchmark_results/100/final_result.csv
cd benchmark_results/100
sha256sum -c checksums.sha256
```

Ciphertext previews are Base64 representations of the first 48 opaque binary
bytes; they do not reveal a choice or count. Timing is split into fresh
encryption, HE tally processing, and complete end-to-end time. The script waits
for each row before starting the next row. It does not start an HTTP server or
process votes in the background.

Large runs still retain three BFV ciphertext files per submitted row. Run 100
then 1,000 before a larger quota to estimate time and disk use.

## Current limitations

- The MVP uses one trustee secret key, not threshold key shares yet.
- The supplied client is trusted to encrypt only A, B, or C.
- Every CSV row is independently encrypted and submitted as its own API
  request; rows are never combined into an input array.
- Each choice creates three separate scalar ciphertexts, and the server stores
  three separate scalar tally ciphertexts. No SIMD packing is used.
- Participation is intentionally visible as token-hash ballot metadata. An
  administrator with the roster can map participation to employees but still
  cannot see their choices.
- This simplified benchmark does not prevent repeated submissions.
- The plaintext modulus is `65537`, so an election must stay below that count.
- The benchmark stores three ciphertext files for every submitted row.
