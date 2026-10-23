# Queries — semantics and reading results

A Verifpal model ends with one `queries[ ]` block: the questions Verifpal answers. A query is
**contradicted** when Verifpal finds a protocol execution that violates it — that execution *is*
the attack, and Verifpal prints it as a witness. **No contradiction** means no violating scenario
was found within the bounded search — read `analysis.md` for why that is not a proof.

> **Results are about scenarios.** If you query authentication for a message Bob never reads and
> see no contradiction, it does **not** mean the message was authenticated. It means "no scenario
> was found in which Bob reads an unauthenticated message." Absence of a contradiction = absence
> of a *contradicting scenario*, nothing stronger.

## confidentiality? v

Contradicted iff the attacker can derive a value equivalent to the resolved form of `v` through
any combination of knowledge-gathering, decomposition, reconstruction, recomposition, and (under
an active attacker) mutation.

- A **passive** attacker needs the key material to appear on the wire (directly or via
  components).
- An **active** attacker can, e.g., replace Bob's public key before Alice encrypts to it, then
  decrypt.

Output form: `m1 (m1) is obtained by Attacker` (possibly listing which wire values the attacker
controlled to get there).

## authentication? A -> B: v

The trickiest query. Reads: "if B successfully uses `v` in its operations, does that necessarily
mean A sent `v` to B?" Formally, Verifpal checks whether `v` is used in any primitive within **B's
(recipient's) state**, and if so whether the recorded **sender** of `v` in that slot is A. If some
execution has B using `v` but its sender is not A (e.g. an active attacker intercepted and
replaced it), the query is **contradicted** — an impersonation.

- Relies on **checked primitives**: authentication is meaningful only where B actually validates
  what it received (`AEAD_DEC(...)?`, `SIGNVERIF(...)?`, `ASSERT(...)?`). Without a check, B "uses"
  attacker-supplied values freely.
- Corresponds to **non-injective agreement** in Lowe's hierarchy: it does *not* guarantee each run
  of B matches a unique run of A, so it does not by itself rule out replay (use `freshness?` for
  that).
- Uses Verifpal's **provenance** tracking: every value carries `creator`, `sender`, and
  `attacker_tainted`. See `analysis.md`.

Output form: `e2, sent by Attacker and not by Bob and resolving to AEAD_ENC(...), is used in
primitive AEAD_DEC(...) in Alice's state`.

## freshness? v

Detects replayability. `v` is **fresh** iff at least one of its transitive components was declared
via `generates` **and** has not been leaked. Fresh values differ each session, so a value built
from one cannot be replayed. Contradicted iff `v` resolves entirely from static (`knows`)
constants, or an active attacker replaced all fresh components with known non-fresh values.

Example: `ha = HASH(a)` with `knows private a` → **contradicted** (static). `hb = HASH(b)` with
`generates b` → **not** contradicted (fresh).

## unlinkability? v, w, …

"For two observed values, the adversary cannot tell whether they belong to the same user or two
different users." Two checks:

1. **Freshness check** — every queried constant must be fresh (as above). Any static value → the
   query is immediately contradicted (static values trivially link sessions).
2. **Common-source check** — if all are fresh, Verifpal checks whether any two resolve to
   *equivalent* values (same primitive, same arguments, differing only in output index) **and**
   the attacker can reconstruct/recompose that primitive from known values. If so →
   contradicted (attacker can tell they share a source).

Example: `h1, h2, h3 = HKDF(a, b, nil)` with attacker-known `a`, `b` → the attacker reconstructs
the HKDF and links `h1`, `h2` → contradicted.

## equivalence? v, w

Contradicted iff some execution makes `v` and `w` resolve to structurally different terms under
the equational theory (including DH commutativity). Passing means in every explored execution they
resolve to the same value. Classic use: check that a DH shared secret computed by each side always
matches (`equivalence? ss_a, ss_b`) — an active attacker substituting an unguarded public key can
make them diverge.

## Query options: precondition

Currently the only option.

```verifpal
authentication? Bob -> Alice: e[
	precondition[Alice -> Carol: m2]
]
```

Reads: "the event *Carol receives m2 from Alice* occurs **only if** Alice previously received and
authenticated `e` as coming from Bob." Ties one message's authentication to a downstream event —
useful when the downstream value (`m2`) is guarded and you want to condition its release on an
earlier authentication.

## Common query-design mistakes

- **Querying a value nobody validates.** Authentication requires the recipient to *use* the value
  in a (usually checked) primitive. Querying auth on a value that's received but never used yields
  a vacuous "no contradiction."
- **Reading "no contradiction" as a proof.** It is a bounded-search result. Vary the model
  (unguard a key, uncheck a primitive, add a phase) and re-run to build confidence.
- **Confusing confidentiality with authentication.** "The attacker can't read it" (confidentiality)
  is independent of "the recipient knows who sent it" (authentication). Most secure-channel goals
  need both.
- **Forgetting freshness for replay.** Authentication is non-injective; if replay matters, add a
  `freshness?` query on the relevant value.
