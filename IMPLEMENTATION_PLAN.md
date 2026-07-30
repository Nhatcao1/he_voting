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

## 3. Encrypted values

The client encrypts a one-hot BFV vector:

```text
A = Enc([1,0,0])
B = Enc([0,1,0])
C = Enc([0,0,1])
```

For each eligible token, the server starts with a separately randomized flag:

```text
encrypted_has_voted = Enc([0,0,0])
```

The shared tally starts as:

```text
encrypted_tally = Enc([0,0,0])
```

## 4. Entire HE calculation

For every request, without decrypting or branching on the flag:

```text
can_vote      = Enc([1,1,1]) - encrypted_has_voted
accepted_vote = can_vote * encrypted_choice
new_tally     = encrypted_tally + accepted_vote
new_flag      = encrypted_has_voted + can_vote
```

First vote:

```text
can_vote = [1,1,1] - [0,0,0] = [1,1,1]
```

Duplicate:

```text
can_vote = [1,1,1] - [1,1,1] = [0,0,0]
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

The native `decrypt-flag` command exists only for automated development tests.
It is not exposed by the API.

## 6. Implemented technologies

| Part | Technology |
|---|---|
| Data generator and clients | Python |
| HE scheme | OpenFHE BFV-RNS |
| HE evaluator | C++17 |
| Web API | FastAPI |
| Ordered state and audit metadata | SQLite |
| Transport in deployment | HTTPS |
| Secret key location | Separate trustee directory |
| Optional future kernel | HEIR-generated OpenFHE C++ |

The BFV parameters use exact integer arithmetic, a plaintext modulus of `65537`,
and OpenFHE's 128-bit classical security setting.

## 7. Evaluator interface

The native application uses:

```text
VoteEvaluator.evaluate(
    encrypted_choice,
    encrypted_has_voted,
    encrypted_tally,
    encrypted_one
)
```

The implemented evaluator is:

```text
HE_EVALUATOR=openfhe
```

The configuration also recognizes:

```text
HE_EVALUATOR=heir-openfhe
```

That option fails closed until a reviewed HEIR-generated kernel is compiled into
the executable. HEIR would compile the fixed four-operation calculation once
and still use OpenFHE at runtime. It is not run for every CSV row.

An evaluator cannot change during an election because its context and
ciphertexts must remain compatible.

## 8. Implemented API

| Route | Purpose |
|---|---|
| `GET /health` | Service and evaluator status |
| `GET /election/public-material` | BFV context and public key |
| `POST /election/vote` | Random voter token plus encrypted A/B/C choice |
| `GET /election/receipt/{id}` | Receipt inclusion check |
| `GET /election/bulletin-board` | Ordered ballot hashes and hash chain |
| `GET /election/encrypted-result` | Final encrypted three-slot tally |
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
2. Re-encrypting the same choice produces different ciphertext bytes.
3. A first vote increments exactly one encrypted counter.
4. A duplicate changes no counter.
5. Two concurrent duplicate submissions count at most once.
6. API responses have the same shape for first and duplicate submissions.
7. The API runtime contains no secret key.
8. The trustee decrypts the expected `[A,B,C]` aggregate.

## 11. Scaling notes

The generator accepts thousands of rows without changing the CSV schema.
Each request is still independently encrypted and sent to the API.

Current limits:

- the plaintext modulus limits the total count to below `65537`;
- every eligible employee currently has a separate BFV flag ciphertext;
- every API request launches the native evaluator process;
- SQLite and one API worker favor correctness over throughput.

Before a very large deployment, benchmark ciphertext storage and replace
per-request process startup with a persistent native evaluator. PostgreSQL can
replace SQLite without changing the HE calculation.

HEIR may optimize or simplify generation of the fixed evaluator, but it does
not generate test rows and does not replace OpenFHE execution.

## 12. Security limitations

- The first version has one trustee secret key, not threshold key shares.
- The supplied client is trusted to encrypt only A, B, or C.
- The server sees repeated random voter tokens, though not employee IDs.
- A malicious client that steals another employee's private token can vote with
  it; secure token distribution is outside this MVP.
- Receipts and a hash chain make stored changes detectable, but do not prevent
  the server from refusing a request before issuing a receipt.
