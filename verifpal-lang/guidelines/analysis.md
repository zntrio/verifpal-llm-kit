# How Verifpal analyzes a model

Verifpal is a **protocol analysis / bug-finding tool**, not a proof-producing verifier. It digests
one protocol execution scenario enacted by explicit principals and tries to find contradictions to
your queries. Understanding the engine tells you what a result means and how to get more insight.

## The verification pipeline

1. **Parsing** — the `.vp` file becomes an AST (attacker, principals + expressions, messages,
   phases, queries).
2. **Sanity checking** — structural validation: phases sequential; every principal named in
   messages/queries is declared; primitive arities match; `?` only on checkable primitives; every
   equation rooted at `G`. (Full list in `grammar.md`.)
3. **Construction** — the model becomes two internal representations:
   - a **protocol trace**: a global, immutable record of every constant's initial value, its
     creator, who knows it, and the phases it's communicated in;
   - a set of **principal states**: per-principal snapshots of each constant's resolved value plus
     metadata (received over the wire? guarded? who may mutate it?).
4. **Verification** — the analysis engine runs, branching on attacker type.

## The deductive analysis loop (fixed point)

Given attacker knowledge `VA` and a principal's state `VP`, three phases repeat until no new value
is derivable:

1. **Decompose** — for each value in `VA`: *active* decomposition (know the required inputs, e.g.
   the key → extract a hidden argument via the DECOMPOSE rule) and *passive* decomposition
   (extract arguments the spec marks as passively revealed, e.g. `ad` in `AEAD_ENC`).
2. **Reconstruct & Recompose** — for each value in `VP`: *reconstruct* (attacker has all
   components → build the value, applied recursively with bounded depth, e.g. a DH shared secret
   from known exponents) and *recompose* (attacker has enough outputs of a multi-output primitive
   to recover an input, e.g. 2 of 3 Shamir shares).
3. **Equivalize, Passwords, Concatenation** — recognize a `VP` value structurally equivalent to a
   known one; extract a `password` value when the attacker can verify a guess (see below); pull
   arguments out of values that reveal them.

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
  attacker-known values are candidates, including `nil` for constants and `G^nil` for equations
  (the attacker's own DH public key). This covers the canonical **DH man-in-the-middle** — replace
  a received `G^b` with `G^nil` — as an ordinary first-order mutation, no special case.
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
primitive normalized with all "secret" parts erased (constants → `nil`, equations → `G`/`G^nil`),
preserving function name, nesting depth, and per-argument type. A candidate must pass: (1)
same cryptographic function, (2) nesting depth ≤ original, (3) a fast skeleton-hash match before
the full structural comparison. This keeps injections structurally compatible with what the
protocol expects.

### Guard bypass

When a checked primitive fails during an active execution, Verifpal doesn't just discard it: if
the attacker can obtain the **bypass key** for the failed primitive (e.g. the symmetric key for
`AEAD_DEC`, the private signing key for `SIGNVERIF`), it constructs a *bypass state* injecting an
attacker-controlled value into the failed slot and re-resolves. This iterates (bounded) to handle
cascading guard failures.

### Preventing state-space explosion

Bounded-depth search + explicit **budgets** (per-principal 80,000 mutation scans per depth;
cross-product cap 50,000 combinations per variable subset; max 150 subsets per weight level) +
early **exhaustion detection** + **skeleton filtering** + **parallelism** (depth levels ≥2 run
concurrently) + **bounded arity** (≤5 in/out). Unlike ProVerif (sound over unbounded sessions via
over-approximation, at the cost of possible non-termination), Verifpal's bounded search always
terminates quickly while covering practically-arising attacks.

## Password extraction

A `password`-qualified constant at position `i` of a primitive `P(a0…an)` known to the attacker is
recoverable iff: (1) position `i` is **not** in `P`'s `password_hashing` list (only `PW_HASH` has a
non-empty one, covering all positions — so `PW_HASH(pwd)` is always safe), **and** (2) the attacker
knows every sibling argument `a_j` (`j ≠ i`). Condition 2 is the offline verification oracle: to
confirm a guess the attacker recomputes the primitive with the guess and compares. Both conditions
are checked at every nesting level. Examples:

- `ENC(pwd, secret)` — attacker lacks `secret`; can't verify a guess → **safe**.
- `ENC(pwd, pubdata)` — attacker knows `pubdata`; brute-forces `ENC(guess, pubdata)` →
  **obtainable**.
- `ENC(key, CONCAT(pwd, data))` — needs `data` (at CONCAT) *and* `key` (at ENC); either unknown →
  **safe**.
- `PW_HASH(pwd)` — protected by condition 1 → **safe**.

Because this runs inside the fixed-point loop, a password may become extractable later once a
sibling is learned by decomposition/reconstruction (cascading attacks).

## Provenance and value resolution

Every value carries a **provenance** record: `creator` (who declared/generated it), `sender` (who
sent it), `attacker_tainted` (did the attacker tamper). If the active attacker replaces `m` on the
wire, `sender` becomes the attacker and `m` is tainted. Authentication queries read this record.

Each state slot tracks three versions: `original` (before tampering), `pre_rewrite` (after
mutation, before rewrites), `value` (final, after both). When resolving nested expressions,
Verifpal uses `original` if the value is untainted, or the principal created it, or it wasn't
received over a wire; it uses the attacker's `value` **only** for values received over the wire
*and* tainted. This makes the analysis reflect what each principal would actually compute.

## Soundness and completeness — the precise boundary

**Guarantees (sound attack-finding):** every reported contradiction is a genuine logical
consequence of the model — no fabricated attacks. The printed trace is a real witness. Specifically:
a contradicted confidentiality query means the attacker legitimately derived the value; a
contradicted authentication query means an execution where the recipient uses the value but its
sender ≠ the claimed sender; a contradicted equivalence query means an execution where the values
resolve to distinct terms.

**Does NOT guarantee:**

- **Verification completeness** — no reported attack is *not* a proof of security; the bounded
  search may miss the mutation combination that reveals a flaw. Bug-finder, not prover.
- **Unbounded sessions** — one scenario (one trace + attacker mutations), not arbitrarily many
  interleaved concurrent sessions. Attacks needing session interleaving / session-id confusion are
  out of scope.
- **Computational soundness** — symbolic model; concrete crypto weaknesses (padding oracles,
  timing side channels, weak RNG, key lengths, cipher modes) are not modelled.

The incompleteness comes from the bounded choice of *which mutations to try*, not from the
deduction within an execution (which is locally complete). In practice the default depth 3 finds
all attacks in published protocols (TLS 1.3, Signal, Noise, Scuttlebutt, DP-3T) within seconds.
