# Primitives and the equational theory

Every Verifpal primitive is defined internally by a common structure called `PRIMITIVESPEC`:
its name, arity (number of inputs), number of outputs, and its behavior expressed via four
standard rule kinds. You cannot define new primitives — this prevents users from mis-specifying
cryptography. All primitives are limited to **at most 5 inputs and 5 outputs**.

## The four rule kinds

- **DECOMPOSE** — given a primitive's output and a subset of its inputs, reveal another input.
  E.g. given `ENC(k, m)` and `k`, reveal `m`. Also marks arguments that are *passively* revealed
  (e.g. the associated data `ad` in `AEAD_ENC(k, m, ad)` is visible to any observer, no key
  needed).
- **RECOMPOSE** — given a subset of a primitive's *outputs*, reveal one of its inputs. E.g. any 2
  of the 3 shares of `SHAMIR_SPLIT(x)` recover `x`. Operates during **attacker analysis**.
- **REWRITE** — given a matching pattern in the inputs, rewrite the whole expression to a simpler
  value. E.g. `DEC(k, ENC(k, m))` → `m`. This encodes the equational relationship between a
  primitive and its inverse.
- **REBUILD** — given a primitive whose inputs are outputs of the same instance of another
  primitive, rewrite to the original input. E.g. `SHAMIR_JOIN(a, b)` where `a, b, c =
  SHAMIR_SPLIT(x)` → `x`. Operates during **symbolic evaluation** (resolving a principal's state),
  whereas RECOMPOSE operates during attacker analysis.

## Core primitives

| Primitive | Output | Notes |
|---|---|---|
| `ASSERT(a, b)` | (unused) | Checks equality of two values (often two MACs). Output is not used — validate by making it **checked** with `?`. |
| `CONCAT(a, b, …)` | `c` | Concatenate 2–5 values into one. Passively reveals all inputs. |
| `SPLIT(CONCAT(a, b, …))` | `a, b, …` | Split a concatenation back into its parts. Input **must** be a `CONCAT` or Verifpal errors. Checkable. |

## Hashing primitives

| Primitive | Output | Notes |
|---|---|---|
| `HASH(a, …)` | `x` | Secure hash (think BLAKE2s). 1–5 inputs, 1 output. |
| `MAC(key, message)` | `hash` | Keyed hash; message authentication, channel binding. |
| `HKDF(salt, ikm, info)` | `a, b, …` | HKDF-style key derivation. Extracts **1–5 outputs** from one secret. `salt`/`info` contextualize. |
| `PW_HASH(a, …)` | `x` | Password hashing (Scrypt/Argon2-like). Use on `knows password` values before using them as keys — resists the offline dictionary attack (its `password_hashing` positions cover all inputs). |

## Encryption primitives

| Primitive | Output | Notes |
|---|---|---|
| `ENC(key, plaintext)` | `ciphertext` | Symmetric encryption (AES-CBC / ChaCha20 flavour). |
| `DEC(key, ENC(key, plaintext))` | `plaintext` | Symmetric decryption. Has a rewrite rule (checkable). |
| `AEAD_ENC(key, plaintext, ad)` | `ciphertext` | Authenticated encryption with associated data. `ad` is **not** encrypted but must match on decrypt. |
| `AEAD_DEC(key, AEAD_ENC(key, plaintext, ad), ad)` | `plaintext` | Authenticated decryption. **Checkable** — `?` aborts on failed auth (wrong key or `ad`). |
| `PKE_ENC(G^key, plaintext)` | `ciphertext` | Public-key encryption (encrypt to a public key `G^key`). |
| `PKE_DEC(key, PKE_ENC(G^key, plaintext))` | `plaintext` | Public-key decryption with the private key. |

## Signature primitives

| Primitive | Output | Notes |
|---|---|---|
| `SIGN(key, message)` | `signature` | `key` is private (e.g. `a`); the public key is `G^a`. |
| `SIGNVERIF(G^key, message, SIGN(key, message))` | `verified` | Verifies a signature. Output is a **verification token, not the message**. Purpose is to be **checked** (`?`) so the protocol aborts on failure. |
| `RINGSIGN(key_a, G^key_b, G^key_c, message)` | `signature` | Ring signature: one of three signs; verifier learns only that *some* ring member signed. First arg = actual signer's **private** key, next two = other members' **public** keys. |
| `RINGSIGNVERIF(G^a, G^b, G^c, m, RINGSIGN(a, G^b, G^c, m))` | `verified` | Verify a ring signature. All three public keys required, **any order**. Checkable. |
| `BLIND(k, m)` | `blinded` | Blind message `m` with secret blinding factor `k`, to send to a signer who signs without seeing `m`. |
| `UNBLIND(k, m, SIGN(a, BLIND(k, m)))` | `SIGN(a, m)` | Unblind: convert a signature over the blinded message into a normal signature by `a` over `m`. |

## Secret sharing primitives

| Primitive | Output | Notes |
|---|---|---|
| `SHAMIR_SPLIT(k)` | `s1, s2, s3` | Split `k` into 3 shares; any **2** reconstruct it. |
| `SHAMIR_JOIN(sa, sb)` | `k` | `sa`, `sb` must be two **distinct** shares from `(s1, s2, s3)`. |

## Checked primitives (`?`)

Checkable primitives: `ASSERT`, `SPLIT`, `AEAD_DEC`, `SIGNVERIF`, `RINGSIGNVERIF` (and the other
rewrite-bearing primitives `DEC`, `PKE_DEC`, `UNBLIND`). Adding `?` makes an instance **checked**:
a failed rewrite becomes a **failed check** that truncates that principal's execution at that
point.

- **Under a passive attacker:** the model runs once with honest values. A failed check means the
  model is invalid — Verifpal reports an error.
- **Under an active attacker:** each mutation combination is a separate execution. A failed check
  truncates *that* execution at the failure point (no later ops for that principal), but values
  obtained *before* the failure remain in the attacker's knowledge and may help other executions.

## The complete equational theory

Applied as left-to-right rewrite rules during symbolic evaluation. This is the **entire** theory —
there is no general unification or algebraic reasoning beyond it, which is what makes analysis
decidable and fast (at the cost of not modelling user-defined algebra).

```
DEC(k, ENC(k, m))                              -> m                    [rewrite]
AEAD_DEC(k, AEAD_ENC(k, m, ad), ad)            -> m                    [rewrite]
PKE_DEC(sk, PKE_ENC(gsk, m))                   -> m                    [rewrite]
SIGNVERIF(gsk, m, SIGN(sk, m))                 -> nil                  [rewrite]
RINGSIGNVERIF(gsk, ..., RINGSIGN(sk, ...))     -> nil                  [rewrite]
UNBLIND(f, SIGN(sk, BLIND(f, m)), m)           -> SIGN(sk, m)          [rewrite]
SPLIT(CONCAT(a, b, ...))                        -> (a, b, ...)          [rewrite]
ENC(k, m)                                       -> m given k            [decompose]
AEAD_ENC(k, m, ad)                              -> ad                   [passive]
BLIND(f, m)                                     -> m given f            [decompose]
CONCAT(a, b, ...)                               -> a, b, ...            [passive]
SHAMIR_SPLIT(s)[i] + SHAMIR_SPLIT(s)[j]         -> s                    [recompose: 2-of-3]
SHAMIR_JOIN(si, sj) when si,sj distinct outputs of SHAMIR_SPLIT(x) -> x [rebuild]
gab = gba                                                              [DH commutativity]
```

Decomposition-rule primitives: `AEAD_ENC`, `AEAD_DEC`, `ENC`, `DEC`, `PKE_ENC`, `PKE_DEC`,
`BLIND`. Rewrite-rule primitives: `ASSERT`, `SPLIT`, `SIGNVERIF`, `DEC`, `AEAD_DEC`, `PKE_DEC`,
`RINGSIGNVERIF`, `UNBLIND`.

## Value construction facts

- Only **constants** can be sent in messages, so the attacker's starting knowledge is constants.
- "Pure" constants (from `knows`/`generates`, not assignment) resolve to themselves (`x -> x`).
- Assigned constants resolve to a primitive or an equation.
- Primitives may take constants, primitives, or equations as arguments but **always return
  constants**.
- Equations take only constants as arguments (they are effectively exponents over `G`).
