# Simple Encrypted Employee Voting — Implemented MVP

## 1. External test data

The generated vote file contains only:

```csv
employee_id,choice
100001,A
100002,B
100003,C
100001,B
```

The last row deliberately duplicates employee `100001`. Its B choice must not
change the final tally.

The separate client-side roster contains:

```text
employee_id
display_name
random per-election voter_token
```

The roster stays with the client. Names and employee IDs are never submitted to
the ballot API.

## 2. Why the API uses a random token

The server needs a way to locate one employee's encrypted `has_voted` flag.
Privately searching and updating thousands of encrypted employee IDs would
require a much larger FHE database circuit.

The client therefore converts its local employee ID to a random 256-bit
per-election voter token. The ballot server stores only a hash of this token.
It cannot map the hash or token back to an employee without obtaining the
private client roster.

This provides a practical lookup while keeping the employee ID out of the API.
The server can recognize that the same random token was submitted again, but
cannot see that token's employee or choice.

## 3. Encrypted scalar values

For every CSV row, the client creates three independent BFV scalar
ciphertexts:

```text
Choice A -> choice_A = Enc(1), choice_B = Enc(0), choice_C = Enc(0)
Choice B -> choice_A = Enc(0), choice_B = Enc(1), choice_C = Enc(0)
Choice C -> choice_A = Enc(0), choice_B = Enc(0), choice_C = Enc(1)
```

These are coefficient-encoded scalar ciphertexts. The implementation does not
pack A, B, and C into SIMD slots.

For each eligible token, the server starts with a separately randomized flag:

```text
encrypted_has_voted = Enc(0)
```

The three shared counters start as separate ciphertexts:

```text
encrypted_tally_A = Enc(0)
encrypted_tally_B = Enc(0)
encrypted_tally_C = Enc(0)
```

## 4. Entire HE calculation

For every request, without decrypting or branching on the flag:

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

First vote:

```text
can_vote = Enc(1) - Enc(0) = Enc(1)
```

Duplicate:

```text
can_vote = Enc(1) - Enc(1) = Enc(0)
```

The API runs the same ciphertext operations and returns the same receipt shape
for first and duplicate submissions.

## 5. Expected duplicate fixture

| Row | Local employee | Choice | Effect |
|---:|---:|:---:|:---|
| 1 | 100001 | A | A + 1 |
| 2 | 100002 | B | B + 1 |
| 3 | 100003 | C | C + 1 |
| 4 | 100001 | B | No change |

Only the aggregate is normally decrypted:

```json
{"A": 1, "B": 1, "C": 1}
```

No flag or individual-ballot decryption command exists. Only the three final
aggregate counters can be passed to the trustee result-decryption operation.

## 6. Implemented technologies

| Part | Technology |
|---|---|
| Application and clients | Python |
| HE scheme | OpenFHE BFV-RNS |
| HE integration | Official `openfhe` Python bindings |
| Web API | FastAPI |
| Ordered state and audit metadata | SQLite |
| Transport in deployment | HTTPS |
| Secret key location | Separate trustee directory |

The BFV parameters use exact integer arithmetic, a plaintext modulus of `65537`,
and OpenFHE's 128-bit classical security setting.

## 7. Persistent Python backend

The complete HE calculation is implemented by:

```text
OpenFHEBackend.evaluate(
    encrypted_choice_A,
    encrypted_choice_B,
    encrypted_choice_C,
    encrypted_has_voted,
    encrypted_tally_A,
    encrypted_tally_B,
    encrypted_tally_C,
    encrypted_one
)
```

The official bindings execute OpenFHE's compiled C++ implementation underneath
Python. The context, public key, and multiplication evaluation keys remain
loaded for the lifetime of the Python process. Every row is still freshly
encrypted and evaluated separately.

## 8. Implemented API

| Route | Purpose |
|---|---|
| `GET /health` | Service and backend status |
| `GET /election/public-material` | BFV context and public key |
| `POST /election/vote` | Random voter token plus three scalar A/B/C ciphertexts |
| `GET /election/receipt/{id}` | Receipt inclusion check |
| `GET /election/bulletin-board` | Ordered ballot hashes and hash chain |
| `GET /election/encrypted-result` | Three separate encrypted scalar totals |
| `GET /election/result` | Trustee-published aggregate |

The API has no decryption endpoint.

## 9. Processing order

```text
receive token and encrypted choice
        |
        v
hash token and locate encrypted flag
        |
        v
run the four HE operations
        |
        v
replace encrypted flag and tally
        |
        v
append ballot hash and chain hash
        |
        v
return receipt
```

The MVP runs exactly one API worker and also uses an in-process lock. Concurrent
duplicate requests are serialized so at most one contributes to the tally.

## 10. Implemented verification

Automated tests verify:

1. The vote CSV has only `employee_id,choice`.
2. Each CSV row is encrypted and submitted separately.
3. Each choice produces three scalar ciphertexts with fresh randomness.
4. Re-encrypting the same choice produces different ciphertext bytes.
5. A first vote increments exactly one encrypted counter.
6. A duplicate changes no counter.
7. Two concurrent duplicate submissions count at most once.
8. API responses have the same shape for first and duplicate submissions.
9. The API runtime contains no secret key.
10. No flag or individual-ballot decryption operation is available.
11. The trustee decrypts only the final A, B, and C aggregate ciphertexts.

## 11. Scaling notes

The generator accepts thousands of rows without changing the CSV schema.
Each request is still independently encrypted and sent to the API.

Current limits:

- the plaintext modulus limits the total count to below `65537`;
- every eligible employee currently has a separate BFV flag ciphertext;
- every row serializes three ballot ciphertexts for durable evidence;
- SQLite and one API worker favor correctness over throughput.

Before a very large deployment, benchmark ciphertext storage. PostgreSQL can
replace SQLite without changing the HE calculation.

## 12. Security limitations

- The first version has one trustee secret key, not threshold key shares.
- The supplied client is trusted to encrypt only A, B, or C.
- The server sees repeated random voter tokens, though not employee IDs.
- A malicious client that steals another employee's private token can vote with
  it; secure token distribution is outside this MVP.
- Receipts and a hash chain make stored changes detectable, but do not prevent
  the server from refusing a request before issuing a receipt.
