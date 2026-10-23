# Primitives and the rewrite theory

Every Verifpal primitive is defined internally by a common structure called `PRIMITIVESPEC`:
its name, arity (number of inputs), number of outputs, and its behavior expressed via standard
rule kinds. You cannot define new primitives — this prevents users from mis-specifying
cryptography. All primitives are limited to **at most 5 inputs and 5 outputs**, with the
THRESHOLD family as the documented exception: shares and join arguments range over 2–16
(`MAX_SHARES = 16` in the engine).

## The rule kinds

- **DECOMPOSE** — given a primitive's output and a subset of its inputs, reveal another input.
  E.g. given `ENC(k, m)` and `k`, reveal `m`; given `AEAD_ENC(k, n, m, ad)` and **both** `k` and
  `n`, reveal `m`. `CONCAT` is the passive case: it reveals all inputs to any observer, no key
  needed. `KEM_ENCAP` decomposes: given the public key (arg 0), it reveals both the shared
  secret (output 0) and the seed (arg 1).
- **RECOMPOSE** — given a subset of a primitive's *outputs*, reveal one of its inputs. E.g. any
  `t` of the `n` shares of `THRESHOLD_SPLIT[t](k)` recover `k`. Operates during **attacker
  analysis**.
- **REWRITE** — given a matching pattern in the inputs, rewrite the whole expression to a simpler
  value. E.g. `DEC(k, ENC(k, m))` → `m`. This encodes the equational relationship between a
  primitive and its inverse.
- **REBUILD** — given a primitive whose inputs are outputs of the same instance of another
  primitive, rewrite to the original input. E.g. `THRESHOLD_JOIN(s1, s2)` where `s1, s2 =
  THRESHOLD_SPLIT[t](x)` → `x`. Operates during **symbolic evaluation** (resolving a principal's
  state), whereas RECOMPOSE operates during attacker analysis. `THRESHOLD_JOIN` additionally
  carries **combine** rules (see the threshold group below).

## Core primitives

| Primitive | Output | Notes |
|---|---|---|
| `ASSERT(a, b)` | (unused) | Checks equality of two values (often two MACs). Output is not used — validate by making it **checked** with `?`. |
| `CONCAT(a, b, …)` | `c` | Concatenate 2–5 values into one. Passively reveals all inputs. |
| `SPLIT(CONCAT(a, b, …))` | `a, b, …` | Split a concatenation back into its parts (1–5 outputs). Input **must** be a `CONCAT` or Verifpal errors. Checkable. |

## Hashing primitives

| Primitive | Output | Notes |
|---|---|---|
| `HASH(a, …)` | `x` | Secure hash (think BLAKE2s). 1–5 inputs, 1 output. |
| `HKDF(salt, ikm, info)` | `a, b, …` | HKDF-style key derivation (Krawczyk scheme). Extracts **1–5 outputs** from one secret. `salt`/`info` contextualize. |
| `MAC(key, message)` | `h` | Keyed hash; message authentication, channel binding. |

## Encryption primitives

| Primitive | Output | Notes |
|---|---|---|
| `ENC(key, plaintext)` | `ciphertext` | Symmetric encryption (AES-CBC / ChaCha20 flavour). Unauthenticated — and therefore the **only** primitive that accepts the `malleable` weakening. |
| `DEC(key, ENC(key, plaintext))` | `plaintext` | Symmetric decryption. Has a rewrite rule, but is **not** checkable. |
| `AEAD_ENC(key, nonce, plaintext, ad)` | `ciphertext` | Authenticated encryption (AES-GCM / ChaCha20-Poly1305 flavour). `ad` is not encrypted but must match exactly on decrypt. **Nonce-reuse attack** (from the spec): the nonce must be unique per key — two encryptions under one key and nonce that differ in plaintext or `ad` let the attacker re-tag either ciphertext under any `ad`; if it also knows either plaintext, it learns the other, the keystream, and can forge any ciphertext under that key and nonce. |
| `AEAD_DEC(key, nonce, AEAD_ENC(key, nonce, plaintext, ad), ad)` | `plaintext` | Authenticated decryption. Fails under the wrong key, nonce or `ad`. **Checkable** — `?` aborts the principal on failed decryption. |
| `PKE_ENC(PUBKEY(key), plaintext)` | `ciphertext` | Public-key encryption, to a public key written `PUBKEY(key)`. |
| `PKE_DEC(key, PKE_ENC(PUBKEY(key), plaintext))` | `plaintext` | Public-key decryption with the private key. Has a rewrite rule, but is **not** checkable. |

## Diffie-Hellman and KEM primitives

| Primitive | Output | Notes |
|---|---|---|
| `PUBKEY(private_key)` | `public_key` | Derives the public key corresponding to a private key. The **same constructor** is used for Diffie-Hellman, signatures, public-key encryption and ring signatures. Its argument may **not** itself be a public key or a shared secret (a `PUBKEY` or `DH_KEX` output). |
| `DH_KEX(public_key, private_key)` | `shared_secret` | Diffie-Hellman key exchange. **Commutative**: `DH_KEX(PUBKEY(a), b)` and `DH_KEX(PUBKEY(b), a)` yield the same shared secret. Arg 0 is the peer's public key, arg 1 your own private value; arg 0 may not be a `DH_KEX`, and arg 1 may not be a `PUBKEY` or `DH_KEX` (no shared secret from two public keys). |
| `KEM_ENCAP(PUBKEY(dk), seed)` | `ss, ct` | Key encapsulation (post-quantum KEM, ML-KEM shape). Takes the recipient's encapsulation key and a random value; binds **two outputs**: the shared secret `ss` and the encapsulation ciphertext `ct`. The seed should be freshly generated — encapsulating twice under the same randomness yields the same shared secret. Arg 0 may not be a `DH_KEX`/`KEM_ENCAP`/`KEM_DECAP` output; arg 1 may not be a `PUBKEY` or `DH_KEX`. A KEM says nothing about *who* encapsulated — authenticate `ct` separately if the recipient needs sender auth. |
| `KEM_DECAP(dk, ct)` | `ss` | Key decapsulation: recovers the shared secret from `ct` using the private key `dk` matching the `PUBKEY(dk)` used to encapsulate. **Checkable** — `?` aborts the principal on failed decapsulation. |

## Signature primitives

| Primitive | Output | Notes |
|---|---|---|
| `SIGN(key, message)` | `signature` | Classic signature. `key` is a **private** key (e.g. `a`); the matching public key is `PUBKEY(key)`. |
| `SIGNVERIF(PUBKEY(key), message, SIGN(key, message))` | `verified` | Verifies a signature. If `a` was used for `SIGN`, then `SIGNVERIF` expects `PUBKEY(a)` as the key. Checkable — the output is a verification token, not the message; the point is the check. |
| `RINGSIGN(key_a, PUBKEY(key_b), PUBKEY(key_c), message)` | `signature` | Ring signature: one of three parties signs; the verifier learns only that *some* ring member signed. First arg = actual signer's **private** key; the next two = the other members' **public** keys, written `PUBKEY(...)`. |
| `RINGSIGNVERIF(PUBKEY(a), PUBKEY(b), PUBKEY(c), m, RINGSIGN(a, PUBKEY(b), PUBKEY(c), m))` | `verified` | Verify a ring signature. The signer's public key must match one of the three; the public keys may appear in **any order**. Checkable. |
| `BLIND(k, m)` | `b` | Blind message `m` with secret blinding factor `k`, to send to a signer who signs without seeing `m`. |
| `UNBLIND(k, m, SIGN(a, BLIND(k, m)))` | `SIGN(a, m)` | Unblind: convert a signature over the blinded message into a normal signature by `a` over `m`. A rewrite primitive; **not** checkable. |

## Threshold primitives

| Primitive | Output | Notes |
|---|---|---|
| `THRESHOLD_SPLIT[t](k)` | `s1, …, sn` | Share `k` so that any `t` of the `n` bound shares recover it, and fewer reveal nothing. The **bracket carries the threshold `t`** (2 ≤ t ≤ n); `n` is the number of shares bound on the left of the `=` (2–16). Any `t` distinct shares recover `k` through `THRESHOLD_JOIN`, and the shares double as the signing shares of `THRESHOLD_SIGN`. |
| `THRESHOLD_JOIN(s1, s2, …)` | `k` | Lagrange interpolation over pieces of one `THRESHOLD_SPLIT` (2–16 args). Given at least `t` **distinct** shares it yields the secret. It also **combines**: (a) at least `t` partial signatures from `THRESHOLD_SIGN` over distinct shares, the same commitments and the same message yield the plain signature `SIGN(k, message)`, which `SIGNVERIF` checks under `PUBKEY(k)`; (b) at least `t` `PUBKEY(share)` values yield `PUBKEY(k)`. Fewer than `t` pieces, a repeated share, a missing commitment, or partials that disagree leave the term unreduced. |
| `THRESHOLD_SIGN(share, nonce, commitments, message)` | `partial` | A signer's share of a threshold signature, FROST round-2 shape. `share` is one output of `THRESHOLD_SPLIT`, `nonce` this signer's fresh secret nonce (FROST's hiding-and-binding nonce pair), `commitments` what the coordinator distributed to bind the session (typically a `CONCAT` of the participants' `PUBKEY(nonce)` commitments — **each nonce's `PUBKEY` commitment must be in the list**; nested `CONCAT` lists are accepted), `message` what is signed. Knowing a partial's nonce, commitments and message reveals its signing share; reusing a nonce under one share breaks the usual nonce-reuse way. Not checkable. |

### Renames from older Verifpal

| Old (≤ 0.52) | Current (1.6.7) |
|---|---|
| `SHAMIR_SPLIT(k)` → 3 shares, any 2 recover | `THRESHOLD_SPLIT[2](k)` — threshold in the bracket, 2–16 shares |
| `SHAMIR_JOIN(sa, sb)` | `THRESHOLD_JOIN(sa, sb, …)` — 2–16 args |

Verifpal itself emits the rename hint: writing `SHAMIR_SPLIT` produces a "now called
`THRESHOLD_SPLIT`" error, and a split now carries its threshold in a bracket, e.g.
`THRESHOLD_SPLIT[2](…)` for two-of-n.

## Checked primitives (`?`)

The checkable set is **exactly six**: `ASSERT`, `SPLIT`, `AEAD_DEC`, `SIGNVERIF`,
`RINGSIGNVERIF`, `KEM_DECAP`. (In older Verifpal `DEC`, `PKE_DEC` and `UNBLIND` were also
checkable; they no longer are — `DEC` and `PKE_DEC` silently return garbage on wrong input, which
is exactly what the dp-3t example's authentication failure teaches.) Adding `?` anywhere else
is a sanity error.

`?` makes an instance **checked**: a failed rewrite becomes a **failed check** that truncates that
principal's execution at that point.

- **Under a passive attacker:** the model runs once with honest values. A failed check means the
  model is invalid — Verifpal reports an error.
- **Under an active attacker:** each mutation combination is a separate execution. A failed check
  truncates *that* execution at the failure point (no later ops for that principal), but values
  obtained *before* the failure remain in the attacker's knowledge and may help other executions.
  In a corrupt-peer scenario run, checked primitives may fail without that being a model error.

## Weakening assumptions (capability brackets)

Per-primitive-instance weakening is declared with **capability brackets** on the primitive:

```verifpal
AEAD_ENC[forgeable](k, n, m, ad)        // this AEAD loses authenticity
HASH[weak from phase 1](x, y)            // this hash loses confidentiality, from phase 1 on
ENC[malleable](k, m)                     // this ciphertext can be reshaped
```

Capabilities (`src/lsp/docs.rs`, `src/primitive/capability.rs`):

- **`weak`** — this primitive **loses confidentiality**: holding the term is enough to recover
  what it protects (whatever its spec marks as revealed under `weak`). Declared for the
  primitives with non-empty `weak_reveals`: `HASH`, `HKDF`-style derivations aside — concretely
  `AEAD_ENC`, `ENC`, `PUBKEY`, `PKE_ENC`, `KEM_ENCAP`, `HASH`.
- **`forgeable`** — this primitive **loses authenticity**: the term becomes constructible without
  its secret argument. Kept separate from `weak` so an authenticated cipher can be forgeable
  while its contents stay unreadable. Declared for primitives with a `forgeable_secret`:
  `AEAD_ENC`, `MAC`, `SIGN`, `THRESHOLD_SIGN`, `RINGSIGN`.
- **`malleable`** — a ciphertext the attacker already holds can be **retargeted** into another
  the recipient still accepts: the symbolic shape of a bit-flipping attack. The attacker must
  already hold a term of the same shape (it licenses reshaping, not conjuring). Because
  malleability is an authenticity loss, an authenticated primitive is pointed at `forgeable`
  instead. **`ENC` is the only primitive that supports `malleable`.**
- **`from phase N`** — delays a capability: it is not in force until phase `N`, and holds from
  there onward (cryptanalysis does not un-happen). A capability arriving later than the message
  it would act on is no capability at all.

Supported-by is **spec-driven**: a capability is rejected (sanity error) on any primitive whose
spec does not support it — `weak` needs non-empty `weak_reveals`, `forgeable` a
`forgeable_secret`, `malleable` a non-empty `malleable_vary`. Core primitives (`ASSERT`,
`CONCAT`, `SPLIT`) carry no cryptographic guarantee to weaken and accept none. Verifpal's error
messages suggest the right alternative (e.g. `weak` on `MAC` → "did you mean `MAC[forgeable]`?").

## The complete rewrite theory

Applied as left-to-right rewrite rules during symbolic evaluation. This is the **entire** theory —
there is no general unification or algebraic reasoning beyond it, which is what makes analysis
decidable and fast (at the cost of not modelling user-defined algebra).

```
DEC(k, ENC(k, m))                                 -> m              [rewrite]
AEAD_DEC(k, n, AEAD_ENC(k, n, m, ad), ad)          -> m              [rewrite]
PKE_DEC(sk, PKE_ENC(PUBKEY(sk), m))               -> m              [rewrite]
KEM_DECAP(dk, ct) over ss, ct = KEM_ENCAP(pk, r)  -> ss             [rewrite]
SIGNVERIF(PUBKEY(k), m, SIGN(k, m))               -> nil            [rewrite]
RINGSIGNVERIF(PUBKEY(a/b/c), m, RINGSIGN(...))    -> nil            [rewrite]
UNBLIND(f, m, SIGN(sk, BLIND(f, m)))              -> SIGN(sk, m)    [rewrite]
SPLIT(CONCAT(a, b, ...))                          -> (a, b, ...)    [rewrite]
THRESHOLD_JOIN(si, sj, ...) over distinct outputs of THRESHOLD_SPLIT[t](x)
                                                  -> x              [rebuild]
THRESHOLD_JOIN over t THRESHOLD_SIGN partials (distinct shares, same
commitments, same message)                        -> SIGN(k, m)     [combine]
THRESHOLD_JOIN over t PUBKEY(share) values        -> PUBKEY(k)      [combine]
DH_KEX(PUBKEY(a), b) == DH_KEX(PUBKEY(b), a)                        [commutativity]
```

Decomposition-rule primitives: `AEAD_ENC` (given key **and nonce**), `AEAD_DEC`, `ENC`, `DEC`,
`PKE_ENC`, `PKE_DEC`, `BLIND`, `KEM_ENCAP` (given the public key, reveals `ss` and the seed),
`THRESHOLD_SIGN` (given nonce, commitments and message, reveals the share). `CONCAT` still
passively reveals its inputs. Rewrite-rule primitives: `ASSERT`, `SPLIT`, `AEAD_DEC`, `DEC`,
`PKE_DEC`, `KEM_DECAP`, `SIGNVERIF` (→ `nil`), `RINGSIGNVERIF` (→ `nil`), `UNBLIND`,
`THRESHOLD_JOIN`.

## Value construction facts

- Only **constants** can be sent in messages, so the attacker's starting knowledge is constants.
- "Pure" constants (from `knows`/`generates`, not assignment) resolve to themselves (`x -> x`).
- Assigned constants resolve to a primitive application. Equations no longer exist — public keys
  and shared secrets are `PUBKEY`/`DH_KEX` primitive applications like any other.
- Primitives may take constants or primitives as arguments but **always return constants**
  (bound on the left of `=`; `_` names an anonymous output the model never uses again).
- `nil` is the public empty value, known to the attacker from the start — the usual "no
  associated data".
