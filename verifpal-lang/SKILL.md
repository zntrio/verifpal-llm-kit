---
name: verifpal-lang
description: >
  Verifpal language and CLI reference — the expert on Verifpal syntax (attacker, principals,
  constants, primitives, equations, messages, phases, queries), the built-in cryptographic
  primitives and their equational theory, guarded constants and checked primitives, and the
  `verifpal` CLI (verify/pretty). Use when writing or debugging the contents of a `.vp` file,
  fixing a parse/sanity error, looking up a primitive's arity or rewrite rule, understanding a
  query's semantics, or reading an attack result. This is for working IN Verifpal at the language
  level — not for deciding WHAT to model or walking the modelling workflow (use verifpal-modelling
  for that), nor for implementing code against a finished model (verifpal-execute-spec). Keywords:
  verifpal, .vp, symbolic model, Dolev-Yao, protocol verification, primitives, guarded constants,
  checked primitives, queries, phases, attacker.
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

queries[ ... ]                // 5. exactly one queries block, last
```

`//` begins a comment. Messages use the ASCII arrow `->` in source (the manual pretty-prints it
as `→`).

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
	knows password pw          // low-entropy secret; guessable unless hashed (see Constants)
	generates a                // fresh random value, unique per session (e.g. an ephemeral key)
	ga = G^a                   // assignment to an equation (Alice's DH/signing public key)
	e1 = AEAD_ENC(ga, m1, c0)  // assignment to a primitive
	leaks m1                   // hand an already-known value to the attacker at this point
]
```

> **"Are you sure it's private?"** A value marked `knows private` is assumed perfectly secret. A
> key baked into a phone (`knows private builtInKey`) is not private if the hardware is reverse
> engineered. Over-claiming privacy models your protocol as stronger than it is.

---

## Fundamental types

Verifpal has exactly three value types: **constants**, **primitives**, **equations**.

### Constants

Named values. Rules that keep models clean:

- **Immutable** — once assigned, a constant cannot be reassigned.
- **Global namespace** — if any principal declares/assigns `c`, no other principal may declare
  `c`, even privately.
- **No referencing** — a constant may be assigned only to a primitive or an equation, never to
  another constant (`x = y` is illegal).

Ways to introduce a constant:

| Form | Meaning |
|---|---|
| `knows public a, b` | Prior knowledge, known to everyone incl. attacker. Static across sessions. |
| `knows private a` | Prior knowledge, secret. Static across sessions. |
| `knows password a` | Prior knowledge, **weak/guessable**. Recoverable by the attacker unless run through `PW_HASH` before use. Models offline dictionary attacks. |
| `generates a` | **Fresh** value, re-randomized every session. Values derived from it are not carried across sessions/executions. The basis of freshness and forward secrecy. |
| `leaks a` | Reveal an already-known constant to the attacker at this point in the model. |
| `a = <primitive\|equation>` | Assignment. `a, b = HKDF(...)` binds multiple outputs. |

`nil` is a built-in public constant (the attacker's "empty" value). `G` is the reserved
Diffie-Hellman generator (see Equations).

### Primitives

Built-in cryptographic (and utility) functions. You **cannot define your own** — this is a
deliberate design choice to stop users mis-defining crypto. Full reference with arities and
rewrite rules in `guidelines/primitives.md`. Quick list:

| Category | Primitives |
|---|---|
| Core | `ASSERT(a, b)`, `CONCAT(a, …)`, `SPLIT(CONCAT(…))` |
| Hashing | `HASH(a, …)`, `MAC(key, msg)`, `HKDF(salt, ikm, info)`, `PW_HASH(a, …)` |
| Encryption | `ENC(k, m)` / `DEC(k, c)`, `AEAD_ENC(k, m, ad)` / `AEAD_DEC(k, c, ad)`, `PKE_ENC(G^k, m)` / `PKE_DEC(k, c)` |
| Signatures | `SIGN(k, m)` / `SIGNVERIF(G^k, m, sig)`, `RINGSIGN(...)` / `RINGSIGNVERIF(...)`, `BLIND(k, m)` / `UNBLIND(...)` |
| Secret sharing | `SHAMIR_SPLIT(k)` → 3 shares, `SHAMIR_JOIN(sa, sb)` → k (any 2 of 3) |

Primitives take constants, primitives, or equations as arguments, but always **return
constants**. Arity is bounded: at most 5 inputs and 5 outputs.

#### Checked primitives (`?`)

`ASSERT`, `SPLIT`, `AEAD_DEC`, `SIGNVERIF`, `RINGSIGNVERIF` (and the other rewrite primitives) are
**checkable**. Suffix `?` to make one **checked**: if its rewrite fails, protocol execution
**aborts at that point** for that principal (no later operations for them are evaluated in that
execution; values obtained earlier still count).

```verifpal
valid = SIGNVERIF(gb, m, sig)?      // abort the session if the signature does not verify
_ = ASSERT(MAC(k, m), tag)?         // abort unless the MAC matches
p = AEAD_DEC(k, c, ad)?             // abort unless authenticated decryption succeeds
```

> **When to check.** Checking every checkable primitive finds *fewer* attacks — it models an
> implementation that always validates. Leaving one unchecked models an implementation that skips
> a real-world check, which can surface interesting attacks. Both are legitimate; choose per the
> behavior you want to study.

`SIGNVERIF`/`RINGSIGNVERIF` output a verification token (not the message); their point *is* the
check. See `guidelines/primitives.md` for how authentication queries lean on checked primitives.

### Equations

Equations capture Diffie-Hellman public keys and shared secrets. Every equation is rooted at the
reserved generator `G`:

```verifpal
ga = G^a          // public key from private a (usable for DH and for SIGN/SIGNVERIF)
gab = ga^b        // shared secret: chained exponentiation
gba = gb^a        // ...equivalent to gab
```

`gab == gba` — Verifpal enforces DH commutativity (internally an equation is a chain of exponents
`[G, x, y]` compared as a commutative multiset). Each step is `base^exponent`; chain to compose.
All equations **must** be rooted at `G`. Equations take only constants as exponents.

The complete fixed **equational theory** (rewrite/decompose/recompose rules) is in
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
say "this value cannot be substituted in a mayor-in-the-middle." Don't reflexively guard
everything — real keys crossing a network are rarely tamper-proof, and leaving them unguarded is
often the more faithful (and more revealing) model.

A principal's *local* state is never affected by attacker mutation on the wire: if the attacker
swaps `e1` for `e2` en route to Bob, Alice still holds her intact `e1`.

---

## Phases

Phases model **temporal** properties — forward secrecy, post-compromise security. Under an active
attacker, `phase[n]` opens a new phase (phases must be sequential: 0, 1, 2, …):

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

## Queries

Exactly one `queries[ ]` block, last in the model. Five query types (formal semantics and worked
readings in `guidelines/queries.md`):

```verifpal
queries[
	confidentiality? m1                        // can the attacker derive m1?
	authentication? Alice -> Bob: e1           // if Bob uses e1, did Alice really send it?
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
| `authentication? A -> B: v` | there is an execution where B uses `v` in a primitive but its recorded sender is not A (non-injective agreement, Lowe's hierarchy). Relies on checked primitives. |
| `freshness? v` | `v` resolves without any non-leaked `generates` component (so it could be replayed). |
| `unlinkability? v, w, …` | any value fails freshness, or two share a common source the attacker can reconstruct. |
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

Reads: "Carol receives `m2` from Alice **only if** Alice previously received and authenticated
`e` as coming from Bob." Links one authentication result to another event.

---

## A complete minimal example

```verifpal
attacker[active]

principal Alice[
	generates a
	ga = G^a
]
Alice -> Bob: ga

principal Bob[
	knows private m1
	generates b
	gb = G^b
	ss_a = ga^b
	e1 = AEAD_ENC(ss_a, m1, gb)
]
Bob -> Alice: gb, e1

principal Alice[
	ss_b = gb^a
	e1_dec = AEAD_DEC(ss_b, e1, gb)?
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
unguarded public keys the attacker runs a full mayor-in-the-middle (replace `ga`/`gb` with
`G^nil`). Guarding the public keys and checking `AEAD_DEC` changes everything.

---

## Running Verifpal (CLI)

```
verifpal verify model.vp     # analyze the model and print query results
verifpal pretty model.vp     # pretty-print / reformat the model
```

Run `verifpal` with no arguments to see the version and options. There is also a VS Code extension
(syntax highlighting, hover docs, live diagrams and analysis) and the browser-based Verifpal
Workbench. Full CLI + tooling notes in `guidelines/cli.md`.

---

## Guidelines

Detailed references — read these when the quick reference above isn't enough:

| File | Contents |
| --- | --- |
| `guidelines/primitives.md` | Every primitive: arity, outputs, decompose/rewrite/recompose/rebuild rules, the complete equational theory, checked-primitive semantics, `PRIMITIVESPEC`. |
| `guidelines/queries.md` | Formal semantics of all five query types + `precondition`; how provenance drives authentication; worked contradiction readings; common query-design mistakes. |
| `guidelines/analysis.md` | How Verifpal analyzes: passive vs active attacker, the fixed-point deduction loop, bounded-depth (d=3) mutation search, skeleton injection, guard bypass, password extraction, provenance, soundness/completeness boundaries. |
| `guidelines/cli.md` | `verify`/`pretty`, installation, VS Code extension, Workbench, reading attack output, model-sharing. |
| `guidelines/grammar.md` | The full BNF grammar of the Verifpal language and the sanity-check rules the parser enforces. |
