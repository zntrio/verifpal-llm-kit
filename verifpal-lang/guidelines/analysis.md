# How Verifpal analyzes a model

Verifpal is a **protocol analysis / bug-finding tool**, not a proof-producing verifier. It digests
protocol execution scenarios enacted by explicit principals and tries to find contradictions to
your queries. Understanding the engine tells you what a result means and how to get more insight.

## The verification pipeline

1. **Parsing** — the `.vp` file becomes an AST (attacker, principals + expressions, messages,
   phases, scenarios, queries). Models given together are analyzed independently.
2. **Sanity checking** — structural validation: phases sequential; every principal named in
   messages/queries/scenarios is declared; primitive arities match; `?` only on the six checkable
   primitives; capability brackets supported by the primitive; THRESHOLD/argument restrictions.
   (Full list in `grammar.md`.)
3. **Scenario expansion** — every declared scenario clones the whole model (principals and
   messages) with the scenario's bindings substituted, and every clone is replicated once per
   session (`--sessions`, see below). Scenario runs multiply with sessions.
4. **Construction** — the expanded model becomes two internal representations:
   - a **protocol trace**: a global, immutable record of every constant's initial value, its
     creator, who knows it, and the phases it's communicated in;
   - a set of **principal states**: per-principal snapshots of each constant's resolved value plus
     metadata (received over the wire? guarded? who may mutate it?).
5. **Verification** — the analysis engine runs, branching on attacker type.

## Scenarios and sessions

- **Scenarios** (the optional `scenarios[ ... ]` block, directly before `queries`): each item is
  a peer configuration — `Principal[target = value, …]` — and Verifpal clones every
  principal/message per scenario, substituting the bindings in the named principal. A scenario
  whose bound values are reachable from a `leaks` declaration is a **corrupt-peer run**: it is
  analyzed (it is where the attacker learns things), but from the phase of that leak onward its
  queries are **not claimed** and its checked primitives may fail without that being a model
  error. Use scenarios when a protocol has more than one plausible peer instantiation (which key
  did the participant actually use?).
- **Sessions** (`verify --sessions N`, default **2**, range 1–16): every principal runs N
  concurrent copies. Known (`knows`) values are **shared** across the copies; `generates` values
  are **freshened** per copy. The attacker can carry values between concurrent runs — this is
  what makes **replay attacks reachable**, and why authentication (injective agreement) fails on
  replay across sessions, not just on forgery. At `--sessions 1` no sibling run exists, so no
  replay can appear by construction. Verdicts are always relative to the session count: raise
  `--sessions` to stress replay resistance.

## Weakening assumptions in analysis

A capability bracket (`AEAD_ENC[forgeable](…)`, `HASH[weak from phase 1](…)`,
`ENC[malleable](…)`) is not documentation — it adds **attacker-owned rules** to the analysis:

- `weak` gives the attacker the marked reveals when it holds the term (confidentiality loss),
- `forgeable` lets it construct the term without the secret argument (authenticity loss),
- `malleable` lets it retarget a ciphertext it already holds (bit-flipping shape),

each optionally **delayed** by `from phase N` — in force from that phase onward only. Declared
capabilities are collected across the model and applied wherever the annotated term (or an
equivalent one) appears.

## The deductive analysis loop (fixed point)

Given attacker knowledge `VA` and a principal's state `VP`, three phases repeat until no new value
is derivable:

1. **Decompose** — for each value in `VA`: *active* decomposition (know the required inputs, e.g.
   the key **and nonce** → extract a hidden argument via the DECOMPOSE rule) and *passive*
   decomposition (extract arguments the spec marks as passively revealed, e.g. `CONCAT` inputs).
2. **Reconstruct & Recompose** — for each value in `VP`: *reconstruct* (attacker has all
   components → build the value, applied recursively with bounded depth) and *recompose*
   (attacker has enough outputs of a multi-output primitive to recover an input, e.g. `t` of the
   `n` shares of a `THRESHOLD_SPLIT[t]`).
3. **Equivalize, Concatenation** — recognize a `VP` value structurally equivalent to a known one;
   pull arguments out of values that reveal them.

Any new knowledge restarts from phase 1. When all three phases add nothing, the loop is at a
**fixed point**. The loop is a **pure fixed-point computation** — it does *not* check queries or
exit early. Query evaluation is a **separate phase** afterward. For a *fixed* set of mutations the
loop is *locally complete*: it derives every value obtainable via the supported rules.

## Passive attacker

Per declared phase: initialize a fresh attacker state; populate `VA` with all public constants,
all leaked constants (this phase), and all wire values; resolve each principal's values, apply
rewrites, run the deduction loop; check queries. One execution per phase suffices — the passive
attacker cannot modify messages.

## Active attacker — bounded-depth mutation search

The active attacker can substitute any **unguarded** wire constant with any value it knows or can
construct, and inject crafted values. Each combination of substitutions is a distinct execution.
The search is parameterized by one **depth `d` (default 3)** with a precise guarantee:

> At depth `d`, Verifpal explores all attacker strategies involving at most `d` simultaneous value
> substitutions, with injected values of nesting depth at most `d`.

Levels:

- **Depth 0 (baseline)** — the unmodified execution (as in passive analysis).
- **Depth 1 (single mutations)** — mutate each unguarded wire constant individually. All
  attacker-known values are candidates, including `nil` for constants and `PUBKEY(nil)` for
  public keys (the attacker's own public key, whose private half it holds). This covers the
  canonical **DH man-in-the-middle** — replace a received `PUBKEY(b)` with `PUBKEY(nil)` — as an
  ordinary first-order mutation, no special case.
- **Depth 2 (pairs)** — pairs of simultaneous mutations plus injection nesting up to depth 1;
  constructed values must share the original's **skeleton** (see below).
- **Depth 3 (triples)** — triples of mutations plus injection nesting up to depth 2.

Per combination: apply mutations to the principal's state → resolve symbolic values → apply
rewrites (a **failed checked primitive truncates** the execution here) → run the deduction loop →
check unresolved queries. If a level yields new knowledge, the mutation map is recomputed with the
expanded knowledge and the search continues. It terminates when all queries are resolved or no new
knowledge is gained at a level (exhaustion).

### Skeleton-based injection

To avoid combinatorial explosion, Verifpal filters candidate injections by **skeleton** — the
primitive normalized with all "secret" parts erased (constants → `nil`, public keys →
`PUBKEY(nil)`), preserving function name, nesting depth, and per-argument type. A candidate must
pass: (1) same cryptographic function, (2) nesting depth ≤ original, (3) a fast skeleton-hash
match before the full structural comparison. This keeps injections structurally compatible with
what the protocol expects. (In 0.52-era Verifpal skeletons normalized equations to `G`/`G^nil`;
since equations are gone, public keys normalize through `PUBKEY` the same way.)

### Guard bypass

When a checked primitive fails during an active execution, Verifpal doesn't just discard it: if
the attacker can obtain the **bypass key** for the failed primitive (e.g. the symmetric key for
`AEAD_DEC`, the private signing key for `SIGNVERIF`), it constructs a *bypass state* injecting an
attacker-controlled value into the failed slot and re-resolves. This iterates (bounded) to handle
cascading guard failures.

### Preventing state-space explosion

Bounded-depth search + explicit **budgets** + early **exhaustion detection** + **skeleton
filtering** + **parallelism** (depth levels ≥2 run concurrently) + **bounded arity** (≤5 in/out,
threshold families capped at 16 shares). Unlike ProVerif (sound over unbounded sessions via
over-approximation, at the cost of possible non-termination), Verifpal's bounded search always
terminates quickly while covering practically-arising attacks.

## Provenance and value resolution

Every value carries a **provenance** record: `creator` (who declared/generated it), `sender` (who
sent it), `attacker_tainted` (did the attacker tamper). If the active attacker replaces `m` on
the wire, `sender` becomes the attacker and `m` is tainted. Authentication queries read this
record — and, since authentication is **injective agreement**, they also read *which session* the
send belongs to: a value honestly sent in session 1 and accepted in session 2 is a replay
contradiction.

Each state slot tracks three versions: `original` (before tampering), `pre_rewrite` (after
mutation, before rewrites), `value` (final, after both). When resolving nested expressions,
Verifpal uses `original` if the value is untainted, or the principal created it, or it wasn't
received over a wire; it uses the attacker's `value` **only** for values received over the wire
*and* tainted. This makes the analysis reflect what each principal would actually compute.

## Soundness and completeness — the precise boundary

**Guarantees (sound attack-finding):** every reported contradiction is a genuine logical
consequence of the model — no fabricated attacks. The printed trace is a real witness.
Specifically: a contradicted confidentiality query means the attacker legitimately derived the
value; a contradicted authentication query means an execution where the recipient uses the value
but its sender is not the claimed sender *in that session* (forgery or replay); a contradicted
equivalence query means an execution where the values resolve to distinct terms.

**Does NOT guarantee:**

- **Verification completeness** — no reported attack is *not* a proof of security; the bounded
  search may miss the mutation combination that reveals a flaw. Bug-finder, not prover.
- **Unbounded sessions** — sessions are bounded (`--sessions`, at most 16); attacks needing more
  concurrent interleavings than analyzed are out of scope. Verdicts are relative to the session
  count.
- **Computational soundness** — symbolic model; concrete crypto weaknesses (padding oracles,
  timing side channels, weak RNG, key lengths, cipher modes) are not modelled — declare a
  **capability** (`weak`/`forgeable`/`malleable`) to weaken a primitive symbolically instead.

The incompleteness comes from the bounded choice of *which mutations to try*, not from the
deduction within an execution (which is locally complete). In practice the default depth 3 finds
all attacks in published protocols (TLS 1.3, Signal, Noise, Scuttlebutt, DP-3T) within seconds.
