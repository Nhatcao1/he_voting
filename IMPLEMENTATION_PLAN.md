# Simple Encrypted Employee Voting — Implemented Design

## 1. Test input

The generated input stays human-readable:

```csv
employee_id,choice
100001,A
100002,B
100003,C
100004,A
```

Every generated row uses a separate employee and is independently encrypted.

The prepared employee list is:

```text
employee_id
display_name
```

The UI loads this list into its employee dropdown.

## 2. Participation and confidentiality

The API receives the selected employee ID. SQLite records:

```text
employees(employee_id, display_name)
ballots(employee_id, ciphertext_path, receipt, audit metadata)
```

Participation is intentionally visible metadata. The application can determine
whether an employee submitted, but it cannot read the encrypted choice. This
simplified MVP does not enforce one submission per employee.

The security boundary is:

```text
Employee participation       visible through employee metadata
Employee A/B/C choice        encrypted
Running A/B/C totals         encrypted
Final aggregate totals       decrypted by the trustee
```

## 3. Per-row choice encryption

Every input row is handled separately. A choice becomes three scalar values:

```text
A -> [1, 0, 0]
B -> [0, 1, 0]
C -> [0, 0, 1]
```

Each scalar is independently encrypted:

```text
choice_a.ct
choice_b.ct
choice_c.ct
```

The implementation does not use SIMD packing or combine multiple rows into one
ciphertext. Re-encrypting the same value produces different randomized
ciphertext bytes.

## 4. Complete HE calculation

Every eligible submission reaches the HE tally function:

```text
new_tally_A = encrypted_tally_A + encrypted_choice_A
new_tally_B = encrypted_tally_B + encrypted_choice_B
new_tally_C = encrypted_tally_C + encrypted_choice_C
```

These are three OpenFHE `EvalAdd` operations. There is no encrypted flag,
subtraction, ciphertext multiplication, or multiplication evaluation key.

The only production decryption operation reads:

```text
tally_a.ct
tally_b.ct
tally_c.ct
```

It cannot accept an individual ballot directory.

## 5. Four-row example

| Row | Employee | Choice | Server status | Encrypted tally effect |
|---:|---:|:---:|:---|:---|
| 1 | 100001 | A | accepted | A + 1 |
| 2 | 100002 | B | accepted | B + 1 |
| 3 | 100003 | C | accepted | C + 1 |
| 4 | 100004 | A | accepted | A + 1 |

The final aggregate is:

```json
{"A": 2, "B": 1, "C": 1}
```

## 6. Components

| Component | Responsibility |
|---|---|
| `python/he_voting/openfhe_backend.py` | BFV setup, row encryption, three additions, aggregate decryption |
| `app/voting_service.py` | Employee metadata, participation, ordered tally updates, receipts |
| `app/api.py` | FastAPI transport and demo UI routes |
| `scripts/generate_data.py` | Test employees, rows, and expected result |
| `scripts/setup_election.py` | Keys, encrypted zero tallies, SQLite runtime |
| `scripts/client.py` | Encrypt and submit one row |
| `scripts/benchmark_votes.py` | Sequential timing and client evidence bundle |
| `scripts/decrypt_result.py` | Trustee-side aggregate-only decryption |

## 7. Client evidence bundle

The benchmark produces:

```text
input_votes.csv
per_vote_times.csv
vote_evidence.csv
participation.csv
expected_result.json
decrypted_result.json
final_result.csv
checksums.sha256
ciphertexts/
├── ballots/
│   └── row_000001/
│       ├── choice_a.ct
│       ├── choice_b.ct
│       └── choice_c.ct
└── final_tally/
    ├── tally_a.ct
    ├── tally_b.ct
    └── tally_c.ct
```

`vote_evidence.csv` shows each test input, its one-hot encoding, server status,
ciphertext filename, byte size, SHA-256 hash, and a short Base64 preview. The
preview is opaque serialized ciphertext data and does not reveal the underlying
scalar.

`participation.csv` maps the prepared employees to submitted/not-submitted
metadata without including any choice.

`final_result.csv` compares the generator's expected counts with the trustee's
decrypted aggregate and identifies the encrypted tally file behind each result.

## 8. Concurrency and scale

One API worker plus an in-process lock serializes encrypted tally file
replacement. Concurrent eligible submissions are processed one at a time and
are all added.

The plaintext modulus is `65537`, so accepted vote counts must remain below that
limit. Disk usage grows mainly because every submitted row retains three
ciphertext files.

## 9. Current limitations

- The MVP uses one trustee secret key rather than threshold shares.
- The supplied client is trusted to encode exactly one of A, B, or C.
- Employee IDs directly link employees to participation.
- Repeated submissions are not prevented in this simplified benchmark.
- The demo employee dropdown is not an authentication mechanism.
- Receipts and the hash chain provide audit evidence but do not force the
  server to accept a request.
