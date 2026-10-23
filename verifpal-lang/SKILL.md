---
name: verifpal-lang
description: >
  Verifpal language and CLI reference — the expert on Verifpal 1.6.7 syntax (attacker,
  principals, constants, primitives, messages, phases, scenarios, sessions, queries), the
  built-in cryptographic primitives and their rewrite theory, guarded constants and checked
  primitives, weakening assumptions (capability brackets), and the `verifpal` CLI
  (verify/pretty/diagram/lsp, result codes, sessions). Use when writing or debugging the
  contents of a `.vp` file, fixing a parse/sanity error, looking up a primitive's arity or
  rewrite rule, understanding a query's semantics, or reading an attack result. This is for
  working IN Verifpal at the language level — not for deciding WHAT to model or walking the
  modelling workflow (use verifpal-modelling for that), nor for implementing code against a
  finished model (verifpal-execute-spec). Keywords: verifpal, .vp, symbolic model, Dolev-Yao,
  protocol verification, primitives, PUBKEY, DH_KEX, guarded constants, checked primitives,
  weakening assumptions, scenarios, sessions, queries, phases, attacker.
---
# Verifpal Language Reference

Verifpal is a tool for verifying the security of cryptographic protocol *designs* in the symbolic
(Dolev-Yao) model. Cryptographic operations are ideal black boxes: the only way to decrypt
`ENC(k, m)` is to know `k`; hashes are unbreakable one-way functions. You describe a protocol as
explicit principals (Alice, Bob, a Server…) who know values, run built-in primitives, and send
messages; then you ask **queries** about confidentiality, authentication, and more.

Verifpal is a **bug-finder, not a prover**: a reported attack is a genuine logical consequence of
the model (sound), but the absence of an attack is *not* a proof of security (not complete). See
`guidelines/analysis.md`.

## Model structure

A `.vp` model always has this top-level shape (full grammar in `guidelines/grammar.md`):

```verifpal
attacker[active]              // 1. exactly one attacker declaration, first

principal Alice[ ... ]        // 2. one or more principal blocks
principal Bob[ ... ]

Alice -> Bob: ga, e1          // 3. messages (interleaved with principals/phases)

phase[1]                      // 4. optional temporal phases

scenarios[ ... ]              // 5. optional peer configurations (at most one block)

queries[ ... ]                // 6. exactly one queries block, last
```

`//` begins a comment (block comments also exist). Messages use the ASCII arrow `->` in source
(the formatter pretty-prints it as `→`). Anything after `queries` is a hard error; the queries
block may be empty only when scenarios are declared.

---

## Declaring the attacker

```verifpal
attacker[passive]   // observes all wire traffic; cannot modify or inject
attacker[active]    // can also mutate unguarded wire values and inject crafted values
```

Exactly one, at the top. Passive is for threat models with no on-path adversary (e.g. air-gapped
systems); active resembles the real threat model for HTTPS, messaging, VPNs, SSH. Guarded
constants and checked primitives only *matter* under an active attacker. See `guidelines/analysis.md`.

---

## Principals

A principal is a named party. Declare its prior knowledge, fresh values, leaks, and assignments
inside `[ ]`. A principal may appear in **multiple blocks** — Verifpal accumulates its state.

```verifpal
principal Alice[
	knows public c0, c1        // known to everyone, including the attacker
	knows private m1           // known only to Alice (be honest — see the caution below)
	generates a                // fresh random value, unique per session (e.g. an ephemeral key)
	ga = PUBKEY(a)             // assignment to a primitive (Alice's public key)
	e1 = AEAD_ENC(k, na, m1, c0)  // assignment to a primitive (nonce as 2nd arg)
	_ = ASSERT(MAC(k, m1), t)? // anonymous output: computed, never used again
	leaks m1                   // hand an already-known value to the attacker at this point
]
```

> **"Are you sure it's private?"** A value marked `knows private` is assumed perfectly secret. A
> key baked into a phone (`knows private builtInKey`) is not private if the hardware is reverse
> engineered. Over-claiming privacy models your protocol as stronger than it is.

Qualifiers are exactly two:

| Qualifier | Meaning |
|---|---|
| `knows public a` | Prior knowledge, known to everyone incl. attacker. Static across sessions. |
| `knows private a` | Prior knowledge, secret. Static across sessions. |

(There is no `knows password` anymore — see Weakening assumptions for how to model weak crypto
instead.)

---

## Fundamental types

Verifpal has exactly two value types: **constants** and **primitives**.

### Constants

Named values. Rules that keep models clean:

- **Immutable** — once assigned, a constant cannot be reassigned.
- **Global namespace** — if any principal declares/assigns `c`, no other principal may declare
  `c`, even privately.
- **No referencing** — a constant may be assigned only to a primitive, never to another constant
  (`x = y` is illegal).
- **Reserved names** — no keyword or primitive name (case-insensitive), no `g`, no
  `unnamed`-prefixed or `attacker`-prefixed names; `_` (anonymous output) is only legal on the
  left of an assignment.

Ways to introduce a constant:

| Form | Meaning |
|---|---|
| `knows public a, b` | Prior knowledge, known to everyone incl. attacker. Static across sessions. |
| `knows private a` | Prior knowledge, secret. Static across sessions. |
| `generates a` | **Fresh** value, re-randomized every session. Values derived from it are not carried across sessions/executions. The basis of freshness and forward secrecy. |
| `leaks a` | Reveal an already-known constant to the attacker at this point in the model. |
| `a = <primitive>` | Assignment. `a, b = HKDF(...)` binds multiple outputs; `_ = ...` names an output the model never uses again. |

`nil` is a keyword: the public empty value, known to the attacker from the start — the usual way
to say "no associated data".

### Primitives

Built-in cryptographic (and utility) functions. You **cannot define your own** — this is a
deliberate design choice to stop users mis-defining crypto. Full reference with arities and
rewrite rules in `guidelines/primitives.md`. Quick list:

| Category | Primitives |
|---|---|
| Core | `ASSERT(a, b)`, `CONCAT(a, …)`, `SPLIT(CONCAT(…))` |
| Hashing | `HASH(a, …)`, `MAC(key, msg)`, `HKDF(salt, ikm, info)` |
| Encryption | `ENC(k, m)` / `DEC(k, c)`, `AEAD_ENC(k, nonce, m, ad)` / `AEAD_DEC(k, nonce, c, ad)`, `PKE_ENC(PUBKEY(k), m)` / `PKE_DEC(k, c)` |
| DH & KEM | `PUBKEY(k)`, `DH_KEX(pub, priv)`, `KEM_ENCAP(PUBKEY(dk), r) → ss, ct`, `KEM_DECAP(dk, ct)` |
| Signatures | `SIGN(k, m)` / `SIGNVERIF(PUBKEY(k), m, sig)`, `RINGSIGN(...)` / `RINGSIGNVERIF(...)`, `BLIND(k, m)` / `UNBLIND(...)` |
| Threshold | `THRESHOLD_SPLIT[t](k)` → 2–16 shares, `THRESHOLD_JOIN(2–16 shares)`, `THRESHOLD_SIGN(share, nonce, commitments, msg)` |

Primitives take constants or primitives as arguments, but always **return constants**. Arity is
bounded: at most 5 inputs and 5 outputs (THRESHOLD families: 2–16 shares/arguments).

#### Checked primitives (`?`)

The checkable set is **exactly six**: `ASSERT`, `SPLIT`, `AEAD_DEC`, `SIGNVERIF`,
`RINGSIGNVERIF`, `KEM_DECAP`. Suffix `?` to make one **checked**: if its rewrite fails, protocol
execution **aborts at that point** for that principal (no later operations for them are evaluated
in that execution; values obtained earlier still count).

```verifpal
valid = SIGNVERIF(gb, m, sig)?      // abort the session if the signature does not verify
_ = ASSERT(MAC(k, m), tag)?         // abort unless the MAC matches
p = AEAD_DEC(k, n, c, ad)?          // abort unless authenticated decryption succeeds
ss = KEM_DECAP(dk, ct)?             // abort unless decapsulation succeeds
```

> **When to check.** Checking every checkable primitive finds *fewer* attacks — it models an
> implementation that always validates. Leaving one unchecked models an implementation that skips
> a real-world check, which can surface interesting attacks. Both are legitimate; choose per the
> behavior you want to study.

`SIGNVERIF`/`RINGSIGNVERIF` output a verification token (not the message); their point *is* the
check. See `guidelines/primitives.md` for how authentication queries lean on checked primitives.

#### Weakening assumptions (capability brackets)

Declare per-instance weak crypto with a bracket on the primitive:

```verifpal
AEAD_ENC[forgeable](k, n, m, ad)     // this AEAD loses authenticity (not confidentiality)
HASH[weak from phase 1](x, y)        // this hash leaks its inputs from phase 1 onward
ENC[malleable](k, m)                 // this ciphertext can be reshaped (ENC only)
```

- **`weak`** — loses confidentiality: holding the term reveals what it protects.
- **`forgeable`** — loses authenticity: the term becomes constructible without its secret.
- **`malleable`** — a held ciphertext can be retargeted into one the recipient still accepts;
  `ENC` is the only primitive supporting it.
- **`from phase N`** — delays the capability until phase N (cryptanalysis doesn't un-happen).

Supported combinations are spec-driven: an unsupported capability on a primitive is a sanity
error with a suggested alternative. Full semantics in `guidelines/primitives.md`.

### DH and public keys

Public keys and DH shared secrets are ordinary primitive applications — there are no equations
anymore (and no reserved `G`):

```verifpal
ga = PUBKEY(a)          // public key from private a (same constructor for DH, SIGN, PKE, rings)
ss_a = DH_KEX(ga, b)    // shared secret: peer's public key, own private value
ss_b = DH_KEX(gb, a)    // ...equivalent to ss_a
```

`DH_KEX(PUBKEY(a), b) == DH_KEX(PUBKEY(b), a)` — commutativity is declared on the primitive.
Restrictions: the arg of `PUBKEY` may not itself be public; `DH_KEX` takes no `DH_KEX` as first
arg and no public value as second (no shared secret from two public keys). The attacker's own
crafted public key is `PUBKEY(nil)`.

The complete fixed **rewrite theory** (rewrite/decompose/recompose/rebuild rules) is in
`guidelines/primitives.md`. There is no general unification — the theory is exactly this fixed
set, which is what makes analysis decidable.

---

## Messages

Messages move constants (only constants) across the network:

```verifpal
Alice -> Bob: ga, e1
Bob -> Alice: [gb], e2
```

An active attacker can read every message. It can also **modify or replace any unguarded
constant** and **inject** crafted values. A **guarded constant** — wrapped in `[ ]` — can still be
*read* by the attacker but **not tampered with**:

```verifpal
Bob -> Alice: [gb], e2   // gb is guarded: models Alice pre-authenticating Bob's public key
```

Guarding a public key models **pre-authentication / mutual authentication**. Guarding is how you
say "this value cannot be substituted in a man-in-the-middle." Don't reflexively guard
everything — real keys crossing a network are rarely tamper-proof, and leaving them unguarded is
often the more faithful (and more revealing) model.

A principal's *local* state is never affected by attacker mutation on the wire: if the attacker
swaps `e1` for `e2` en route to Bob, Alice still holds her intact `e1`.

---

## Phases

Phases model **temporal** properties — forward secrecy, post-compromise security. Under an active
attacker, `phase[n]` opens a new phase (phases must increment by exactly 1):

```verifpal
Bob -> Alice: b1
phase[1]
principal Alice[leaks a2]
```

Semantics:

- **Knowledge** — the attacker learns a value in the earliest phase it is communicated. Above, it
  learns `b1` in phase 0 and `a2` in phase 1.
- **Manipulation** — the attacker can only *mutate/inject* a value in a phase where that value is
  communicated. It knows `b1` in phase 1 but can only tamper with it in phase 0.
- **No cross-phase mutation reuse** — values derived from a phase-0 mutation cannot build new
  values in phase 1.

Typical use: leak long-term keys in `phase[1]` *after* a session ran in `phase[0]` to test whether
past messages stay secret (forward secrecy). See `examples/signal.vp`.

---

## Scenarios and sessions

- The optional `scenarios[ ... ]` block (directly before `queries`, at most one) lists **peer
  configurations**: `Principal[target = value, …]`. Verifpal clones every principal/message per
  scenario and substitutes the bindings. A scenario whose bound values are reachable from a
  `leaks` declaration is a **corrupt-peer run**: analyzed, but its queries are not claimed. Use it
  when the protocol has more than one plausible peer instantiation.
- `verify --sessions N` (**default 2**, range 1–16) replicates every principal N times with
  freshened generated values; the attacker can carry values between concurrent runs — this is
  what makes **replay attacks reachable**. Verdicts are relative to the session count.

---

## Queries

Exactly one `queries[ ]` block, last in the model. Five query types (formal semantics and worked
readings in `guidelines/queries.md`):

```verifpal
queries[
	confidentiality? m1                        // can the attacker derive m1?
	authentication? Alice -> Bob: e1           // if Bob uses e1, did Alice really send it — this session?
	freshness? h                               // is h fresh (not replayable across sessions)?
	unlinkability? a, b, c                     // can the attacker link these as same-source?
	equivalence? ss_a, ss_b                    // do these always resolve to the same value?
]
```

A query is **contradicted** when Verifpal finds a scenario violating it — that is the "attack." No
contradiction means "no violating scenario was found in the bounded search," *not* a proof.

| Query | Contradicted when… |
|---|---|
| `confidentiality? v` | the attacker can derive a value equal to the resolved `v`. |
| `authentication? A -> B: v` | there is an execution where B uses `v` in a primitive but its recorded sender is not A in this session (**injective agreement** — fails on forgery AND on replay across sessions). Relies on checked primitives. |
| `freshness? v` | `v` resolves without any non-leaked `generates` component, or an active attacker can force it to stay the same across sessions and get it accepted again. |
| `unlinkability? v, w, …` | any two of the (≥2 distinct) constants link: observed equality, a check succeeding over both under one key, a shared secret origin, or a confirmable embedded secret. |
| `equivalence? v, w` | some execution makes `v` and `w` resolve to structurally different terms. |

### Query options

Currently only `precondition`:

```verifpal
queries[
	authentication? Bob -> Alice: e[
		precondition[Alice -> Carol: m2]
	]
]
```

Reads: restrict the query to executions where the message `Alice -> Carol: m2` **is sent** (the
event is the send itself — not receipt, not authentication). The model must contain the message.

---

## A complete minimal example

```verifpal
attacker[active]

principal Alice[
	generates a
	ga = PUBKEY(a)
]
Alice -> Bob: ga

principal Bob[
	knows private m1
	generates b, nb
	gb = PUBKEY(b)
	ss_a = DH_KEX(ga, b)
	e1 = AEAD_ENC(ss_a, nb, m1, gb)
]
Bob -> Alice: gb, nb, e1

principal Alice[
	generates na
	ss_b = DH_KEX(gb, a)
	e1_dec = AEAD_DEC(ss_b, nb, e1, gb)?
]

queries[
	confidentiality? e1
	confidentiality? m1
	authentication? Bob -> Alice: e1
	equivalence? ss_a, ss_b
]
```

Under a **passive** attacker: `e1` is observable but `m1` stays secret; no auth/equivalence
contradiction. Under an **active** attacker: all four are contradicted — with unauthenticated,
unguarded public keys the attacker runs a full man-in-the-middle (replace `ga`/`gb` with
`PUBKEY(nil)`). Guarding the public keys and checking `AEAD_DEC` changes everything.

---

## Running Verifpal (CLI)

```
verifpal verify model.vp                  # analyze the model and print query results
verifpal verify model.vp --result-code    # compact c/a/f/u/e + 0/1 code per query
verifpal verify model.vp --sessions 3     # stress replay with more concurrent sessions
verifpal pretty model.vp                  # reformat the model
verifpal diagram model.vp                 # Mermaid sequence diagram
```

Run `verifpal` with no arguments to see the version and options. Exit status: 0 normal, 1 run
failure, 2 with `--fail-on-attack` when a query is broken. There are editor extensions (VS Code,
Neovim, Zed — live diagnostics and analysis via `verifpal lsp`) and the browser-based Verifpal
Workbench. Full CLI + tooling notes in `guidelines/cli.md`.

---

## Guidelines

Detailed references — read these when the quick reference above isn't enough:

| File | Contents |
| --- | --- |
| `guidelines/primitives.md` | Every primitive: arity, outputs, decompose/rewrite/recompose/rebuild rules, the complete rewrite theory, checked-primitive semantics, weakening assumptions (capability brackets), renames from pre-1.0 Verifpal. |
| `guidelines/queries.md` | Formal semantics of all five query types + `precondition`; injective agreement and sessions; how provenance drives authentication; worked contradiction readings; common query-design mistakes. |
| `guidelines/analysis.md` | How Verifpal analyzes: the pipeline with scenario expansion and sessions, passive vs active attacker, the fixed-point deduction loop, bounded-depth (d=3) mutation search, skeleton injection, guard bypass, weakening assumptions in analysis, provenance, soundness/completeness boundaries. |
| `guidelines/cli.md` | `verify` (flags incl. `--result-code`, `--sessions`, `--fail-on-attack`, `--auto-queries`, `--format`), `pretty`, `diagram`, `about`, `lsp`, `completion`; exit statuses; reading attack output; building from source; editor extensions and the Workbench. |
| `guidelines/grammar.md` | The full BNF grammar of the Verifpal language (scenarios, capability brackets, no equations) and the sanity-check rules the parser enforces. |
