---
name: verifpal-modelling
description: >
  Model a cryptographic protocol in Verifpal and analyze its security. Use this whenever the user
  wants to model, spec out, formally describe, or security-analyze a protocol in Verifpal — e.g.
  "model this handshake in Verifpal", "check this key exchange for MITM", "does this protocol have
  forward secrecy", "analyze this design against an active attacker" — even if they never say
  "Verifpal". It builds the `.vp` model from whatever the user has (an idea developed
  interactively, a requirements/spec document, or source code) and walks the modelling flow
  (attacker, principals, messages, guards, checks, phases, queries), then drives the tweak-and-rerun
  analysis loop that is the heart of Verifpal. Also use this to **review or audit an existing `.vp`
  model** — "review my model", "is this Verifpal model right", "is it over-claiming security". Do
  NOT use this for pure language/CLI/primitive lookups (that's verifpal-lang) or for implementing
  code against a finished, trusted model (that's verifpal-execute-spec). For syntax, primitives,
  and the analysis engine, defer to the verifpal-lang reference.
---

# Verifpal Modelling

Produce a Verifpal (`.vp`) model of a cryptographic protocol and analyze its security goals. This
skill owns the **modelling discipline** (below) and **routes** to a flow-specific guideline for
the intake — turning a particular kind of input (an idea, a requirements doc, source code, or an
existing model to audit) into the understanding the shared steps build on.

For language syntax, the built-in primitives, the equational theory, the CLI, and how the analysis
engine works, defer to the **verifpal-lang** reference. This skill is about *how to model and
analyze*, not Verifpal syntax.

---

## Pick the flow

Identify what the user is starting from, then read the matching guideline. It handles **intake** —
extracting the protocol's principals, values, operations, messages, and security goals from that
source. After intake, everyone converges on the **Shared modelling spine** below.

| Starting point | Flow | Guideline |
|---|---|---|
| Only an idea / informal protocol sketch, built interactively | **from nothing** | `guidelines/from-nothing.md` |
| A written protocol spec / RFC / requirements document | **from requirements** | `guidelines/from-requirements.md` |
| An implementation (Rust, Go, TypeScript, …) | **from code** | `guidelines/from-code.md` |
| A **finished `.vp` model to audit**, not build | **review** | `guidelines/review.md` |

The first three are **build** flows: intake → the spine below. The **review** flow is different —
no new model to produce; you audit an existing model against a checklist and report. Read
`guidelines/review.md` and follow it directly.

If the starting point is ambiguous ("a design doc with some pseudocode"), ask the user which
source is authoritative before picking — the intake differs materially.

---

## Two principles that hold throughout

- **Analyzable early, tweak often.** A `.vp` model runs the moment it's syntactically complete.
  Run `verifpal verify model.vp` as soon as you have one principal, one message, and one query —
  don't write the whole protocol before analyzing. And the *central Verifpal activity is not
  writing the model once — it's tweaking it and re-running.* Guard a key / unguard it, check a
  primitive / uncheck it, make a constant public / private, add a phase and leak a key: each small
  edit turns a secure result into an attack (or vice versa) and *that contrast is the insight*.
  Every bundled example in `examples/` has an "experiments" banner listing exactly these edits.

- **Model the what, not the how.** Verifpal is symbolic: primitives are ideal black boxes. Model
  observable protocol structure — who knows what, who sends what, which operations run — and
  abstract away serialization, key lengths, cipher modes, retries, memory. IDs are opaque
  constants. If a detail can't affect a query, it doesn't belong in the model. Verifpal is a
  **bug-finder, not a prover**: a reported attack is real; the absence of one is not a proof (see
  verifpal-lang `guidelines/analysis.md`). Say this to the user so results aren't over-trusted.

### Reference examples

Four complete, analyzable models are bundled in `examples/`, ordered by complexity. Read the
closest structural match as a worked instance of the spine — see `examples/README.md` for the
selection table. In short: `challenge-response.vp` (smallest — teaches checks + guards),
`signal.vp` (two-party session, ratchet, forward secrecy via phases), `scuttlebutt.vp` (adds a
pre-shared symmetric key), `dp-3t.vp` (multi-party, time-staged).

---

## Shared modelling spine

Every build flow lands here. Intake produces an **understanding** of the protocol: its principals
and roles, what each knows or generates, the operations they perform, the messages they exchange,
and the security goals. The spine turns that into an analyzed `.vp` model.

### Step 1 — Fix the use case, principals, and security goals

Before any syntax, answer three questions (the intake guideline fills these from its source):

| Concern | Questions |
|---|---|
| **Use case & threat model** | What is the protocol for? Is there an on-path adversary? → almost always `attacker[active]`; use `attacker[passive]` only for genuinely no-active-attacker settings (air-gapped, cleared operators). |
| **Principals & roles** | Who are the parties (Alice, Bob, Server, Client, Smartphone…)? What does each **know** ahead of time (public? private? a weak password?) and **generate** fresh per session? |
| **Security goals** | For each sensitive value: confidentiality? authentication (who must have sent it)? freshness / replay resistance? unlinkability? forward secrecy / post-compromise? These become the `queries[ ]` block — decide them **now**, they drive the whole model. |

> **Be honest about `private`.** A value is only as secret as reality allows. Marking a
> device-embedded key `knows private` when the hardware can be reverse-engineered models the
> protocol as stronger than it is. Over-claiming privacy is the most common way to get a
> falsely-secure result.

Verifpal models **one execution scenario**. If the protocol can unfold multiple ways (group chat
ordering, a late joiner, out-of-order messages), pick one scenario per model and write **several
models** applying the same queries to explore each — that comparison is itself the analysis.

### Step 2 — Declare the attacker and the principals' initial state

```verifpal
attacker[active]

principal Alice[
	knows public c0
	knows private m1
	generates a
	ga = G^a
]
```

Use `knows public` for anything the attacker also has, `knows private` for genuine secrets,
`knows password` for low-entropy secrets (and remember to `PW_HASH` them before use), `generates`
for per-session freshness (ephemeral keys, nonces — the basis of forward secrecy). A principal can
be declared across **multiple blocks**; state accumulates. Get the knowledge right first — typecheck
by running `verifpal verify` on this skeleton before adding operations.

### Step 3 — Model each principal's operations (assignments)

Translate each protocol computation into an **assignment** to a built-in primitive or equation —
never invent crypto, use verifpal-lang's primitive table. Model the operation's *effect*, not its
implementation:

```verifpal
principal Bob[
	generates b
	gb = G^b                              // DH public key (equation, rooted at G)
	ss = ga^b                             // DH shared secret
	e1 = AEAD_ENC(ss, m1, gb)             // authenticated encryption; gb as associated data
]
```

Multi-output primitives bind several constants: `k1, k2 = HKDF(salt, ikm, info)`. Keep to small
key schedules that capture the real key-derivation structure. Run `verifpal verify` after each
principal — a sanity/arity error surfaces immediately.

### Step 4 — Model the messages, and decide guards deliberately

Only constants cross the wire. For each message decide, per value, whether it is **guarded**:

```verifpal
Alice -> Bob: ga, e1
Bob -> Alice: [gb], e2     // gb guarded: Alice has pre-authenticated Bob's public key
```

A guarded `[c]` can be read by the active attacker but not substituted — this is how you model
**pre-authentication / mutual authentication**. Guarding is a modelling *decision with
consequences*: guard the public keys and a man-in-the-middle vanishes; leave them unguarded and
Verifpal finds it. Don't reflexively guard everything — the unguarded version is often the more
faithful and more revealing model. Plan to analyze **both**.

### Step 5 — Decide which primitives are checked

Suffix `?` on a checkable primitive (`AEAD_DEC`, `SIGNVERIF`, `ASSERT`, `SPLIT`, `RINGSIGNVERIF`,
`DEC`, `PKE_DEC`, `UNBLIND`) to make the session **abort** if its rewrite fails:

```verifpal
valid = SIGNVERIF(gb, m, sig)?
p = AEAD_DEC(k, c, ad)?
```

Checking models an implementation that validates; **authentication queries depend on it** (an
unchecked recipient "uses" attacker values freely, see verifpal-lang `guidelines/queries.md`).
Checking everything finds fewer attacks; deliberately leaving a check off models an implementation
that skips a real-world validation and can reveal a bug. Like guarding, this is a knob to turn
across runs.

### Step 6 — Add phases only for temporal goals

For forward secrecy / post-compromise security, run the session in `phase[0]` and then, in
`phase[1]` (or later), `leaks` the long-term keys — testing whether *past* messages stay secret
after a later compromise:

```verifpal
phase[1]
principal Alice[leaks alongterm]
principal Bob[leaks blongterm]
```

Phases require an active attacker and must be sequential. Skip them entirely if the protocol has
no temporal property to test. See `examples/signal.vp` and `examples/dp-3t.vp`.

### Step 7 — Write the queries

The `queries[ ]` block (last, exactly one) encodes the Step 1 security goals:

```verifpal
queries[
	confidentiality? m1
	authentication? Alice -> Bob: e1
	freshness? nonce
	equivalence? ss_a, ss_b
]
```

Each query type's exact contradiction condition is in verifpal-lang `guidelines/queries.md`. Query
authentication only on values the recipient actually **uses in a (checked) primitive** — otherwise
the result is vacuous.

### Step 8 — Analyze, then tweak and re-analyze

Run `verifpal verify model.vp`. Read every `Result` line as a concrete attack witness (a `G^nil`
in the trace is the attacker's crafted DH key — a man-in-the-middle fingerprint). A clean run
means "no contradicting scenario found in the bounded search," **not** a proof.

Then do the thing Verifpal is *for*: **tweak and re-run.** Systematically flip the knobs from Steps
4–6 and observe how results change:

- unguard a public key → expect a man-in-the-middle
- uncheck a `SIGNVERIF`/`AEAD_DEC` → expect impersonation / acceptance of forged values
- make a `private`/`password` constant `public` → test the pre-shared-secret assumption
- add a `phase[1]` leak → test forward secrecy

Each contrast is a finding. Record which configuration achieves which goal — that mapping is the
deliverable, not a single green run.

### Step 9 — Self-review and hand off

Before handing the model over, run the quick self-check (the full checklist is
`guidelines/review.md`):

- **Honest `private`** — nothing marked private that reality wouldn't keep secret.
- **Deliberate guards & checks** — every `[ ]` and every `?` is a conscious modelling decision you
  can justify, and you analyzed the un-guarded / un-checked variants too.
- **Queries match the goals** — every Step-1 goal has a query; authentication queries target
  values the recipient actually uses.
- **One clear scenario** — the model is one coherent execution; alternate scenarios are separate
  models.
- **Results interpreted honestly** — contradictions reported as real attacks; clean runs reported
  as "no attack found in bounded search," not proofs.

Produce a short record (comment block or `README`) covering **what the model covers** (principals,
which goals, which guards/checks/phases and why), **what it does not** (idealized assumptions —
e.g. a value assumed private that may not be; single-scenario limits; no unbounded sessions or
computational attacks), and **which tweaks produced which results**. This honesty note is what
stops the model from being over-trusted.

---

## Conventions

- **Names:** `Alice`/`Bob` for peers, `Client`/`Server`, descriptive role names (`SmartphoneA`,
  `BackendServer`, `HealthCareAuthority`). Long-term keys `along term`/`blongterm` style; ephemeral
  `ae1`, `be`; public keys prefixed `g` (`ga = G^a`); shared secrets `ss`/`kshared`; ciphertexts
  `e1`, `secretBox…`.
- **`G` and `nil`** are reserved: `G` the DH generator, `nil` the public empty constant (and the
  attacker's `G^nil` key). Don't redeclare them.
- **Abstraction:** opaque IDs, no string manipulation, `HASH`/`HKDF` for key schedules, `CONCAT`
  for structured payloads. Don't model wire formats.
- **Scenario size:** two or three principals and a handful of messages capture most goals and keep
  analysis fast. Model one message flow first, analyze, then extend.

For everything syntactic — the full primitive list, arities, the equational theory, the CLI,
result output, the grammar — consult the **verifpal-lang** reference rather than reproducing it
here.
