# Queries — semantics and reading results

A Verifpal model ends with one `queries[ ]` block: the questions Verifpal answers. A query is
**contradicted** when Verifpal finds a protocol execution that violates it — that execution *is*
the attack, and Verifpal prints it as a witness. **No contradiction** means no violating scenario
was found within the bounded search — read `analysis.md` for why that is not a proof.

> **Results are relative to the session count.** By default Verifpal analyzes the protocol as
> running **2 concurrent sessions** of every principal (`--sessions`, default 2, range 1–16).
> The attacker can carry values between concurrent runs, which is what makes replay attacks
> reachable. A query reported as holding at `--sessions 1` may break at `--sessions 2`; verdicts
> are always "for this session count."

## confidentiality? v

Contradicted iff the attacker can derive a value equivalent to the resolved form of `v` through
any combination of knowledge-gathering, decomposition, reconstruction, recomposition, and (under
an active attacker) mutation.

- A **passive** attacker needs the key material to appear on the wire (directly or via
  components).
- An **active** attacker can, e.g., replace Bob's public key (`PUBKEY(b)` → `PUBKEY(nil)`)
  before Alice encrypts to it, then decrypt.

Output form: `m1 (m1) is obtained by Attacker` (possibly listing which wire values the attacker
controlled to get there).

## authentication? A -> B: v

The trickiest query. Reads: "if B successfully uses `v` in its operations, does that necessarily
mean A sent `v` to B — **in this very session**?" Verifpal checks whether `v` is used in any
primitive within **B's (recipient's) state**, and if so whether the recorded **sender** of `v` in
that slot is A, in this session. This is **injective agreement** in Lowe's hierarchy:

- It fails when the attacker can **forge** `v` (B uses a value A never sent), **and**
- it fails when the attacker can **replay** an `v` A sent once and make B accept it again in
  another session (each run of B must match a *distinct* run of A).

Replays need two runs to appear, which is why the default session count is 2 — at
`--sessions 1` there is no sibling run to replay into. Raise `--sessions` to stress replay
resistance; verdicts are relative to the session count.

- Relies on **checked primitives**: authentication is meaningful only where B actually validates
  what it received (`AEAD_DEC(...)?`, `SIGNVERIF(...)?`, `ASSERT(...)?`, `KEM_DECAP(...)?`).
  Without a check, B "uses" attacker-supplied values freely.
- Uses Verifpal's **provenance** tracking: every value carries `creator`, `sender`, and
  `attacker_tainted`. See `analysis.md`.

Output form: `e2, sent by Attacker and not by Bob and resolving to AEAD_ENC(...), is used in
primitive AEAD_DEC(...) in Alice's state`.

## freshness? v

Detects replayability. `v` is **fresh** iff at least one of its transitive components was declared
via `generates` **and** has not been leaked. Fresh values differ each session, so a value built
from one cannot be replayed.

- Under a **passive** attacker, the query simply asks whether the value contains something
  freshly generated.
- Under an **active** attacker, it also asks whether the attacker can **force the value to stay
  the same across sessions** and then **get it accepted again** — i.e., mount the replay rather
  than merely observe sameness.

Example: `ha = HASH(a)` with `knows private a` → **contradicted** (static). `hb = HASH(b)` with
`generates b` → **not** contradicted (fresh).

## unlinkability? v, w, …

"Can the attacker link two of the given values as same-source?" Takes **at least two distinct
constants**. The query is contradicted if any pair links by any of **four mechanisms**:

1. **Observed equality** — the attacker observes the two values equal.
2. **A check succeeding over both under one key** — a decryption or signature verification that
   succeeds over both under one participant's key.
3. **A secret they share as their origin** — a common secret both descend from.
4. **A secret the attacker can confirm sits inside both** — a confirmable embedded secret.

Example: `h1, h2, h3 = HKDF(a, b, nil)` with attacker-known `a`, `b` → the attacker reconstructs
the HKDF and links `h1`, `h2` → contradicted.

## equivalence? v, w

Contradicted iff some execution makes `v` and `w` resolve to structurally different terms under
the rewrite theory (including `DH_KEX` commutativity, declared on the primitive itself). Passing
means in every explored execution they resolve to the same value. Takes **at least two distinct
constants**. Classic use: check that a DH shared secret computed by each side always matches
(`equivalence? ss_a, ss_b` where `ss_a = DH_KEX(ga, b)` and `ss_b = DH_KEX(gb, a)`) — an active
attacker substituting an unguarded public key can make them diverge.

## Query options: precondition

Currently the only option.

```verifpal
authentication? Bob -> Alice: e[
	precondition[Alice -> Carol: m2]
]
```

The option restricts the query to the **executions in which the named message is sent**: the
query is contradicted only where its own condition fails and the sender still reaches that send.
The event is the **send itself** — not its receipt, not its authentication. The model must contain
the named message, or the query is rejected.

Useful when a downstream value (`m2`) is guarded and you want to condition its release on an
earlier event.

## Common query-design mistakes

- **Querying a value nobody validates.** Authentication requires the recipient to *use* the value
  in a (usually checked) primitive. Querying auth on a value that's received but never used yields
  a vacuous "no contradiction."
- **Reading "no contradiction" as a proof.** It is a bounded-search result. Vary the model
  (unguard a key, uncheck a primitive, add a phase, raise `--sessions`) and re-run to build
  confidence.
- **Confusing confidentiality with authentication.** "The attacker can't read it"
  (confidentiality) is independent of "the recipient knows who sent it" (authentication). Most
  secure-channel goals need both.
- **Forgetting replay stress.** Authentication is injective, but only relative to the analyzed
  session count — at `--sessions 1` no replay can appear by construction. Where replay matters,
  analyze at 2+ sessions before believing a pass.
