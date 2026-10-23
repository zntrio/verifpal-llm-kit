# Reviewing / auditing an existing Verifpal model

Use this flow when the user hands you a finished `.vp` model to audit rather than build — "review
my model", "is this right", "is it claiming more security than it proves". There is no new model
to produce: you check the existing one against the checklist below and report findings. Read the
model, run it, and for each finding cite the exact line.

Run `verifpal verify model.vp` first and keep the output beside you — several checks compare what
the model *claims* against what the analysis actually *shows*.

## C1 — Honest privacy (the #1 over-claim)

- Every `knows private` value: would reality actually keep it secret? Device-embedded keys,
  "pre-shared" values known to a whole network, anything derivable by an attacker — flag each.
- A model that marks too much `private` produces a falsely-secure result. This is the most common
  and most dangerous defect. If the real system's crypto is *weaker* than the ideal primitive,
  the honest model declares a **weakening assumption** (`[weak]`/`[forgeable]`/`[malleable]`)
  rather than pretending the primitive is ideal.

## C2 — Deliberate guards

- Every guarded `[c]`: is pre-authentication of that value *realistic*? Guarding all public keys
  often models a world that doesn't exist (keys are rarely tamper-proof on the wire).
- Is there an **unguarded** counterpart run? A model that only ever guards keys hides the
  man-in-the-middle it should be surfacing. A proper audit analyzes both.
- Conversely, a value the protocol genuinely pre-authenticates but the model left unguarded may
  produce a spurious attack.

## C3 — Deliberate checks

- Every checkable primitive (the checkable set is exactly `ASSERT`, `SPLIT`, `AEAD_DEC`,
  `SIGNVERIF`, `RINGSIGNVERIF`, `KEM_DECAP`): is it `?`-checked where the real protocol
  validates, and left unchecked where the real protocol (or the code being modelled) skips
  validation? (`DEC` and `PKE_DEC` are **not** checkable — an unchecked `DEC` silently returns
  garbage, which is itself a modelling statement.)
- **Authentication queries require checks.** If the model queries `authentication?` on a value the
  recipient never uses in a *checked* primitive, the passing result is vacuous — call it out.

## C4 — Queries match the stated goals

- Does every security goal the model claims to test have a corresponding query? Missing queries =
  untested claims.
- Are authentication queries targeting values the recipient actually **uses in a primitive**
  (verifpal-lang `guidelines/queries.md`)? A query on a received-but-unused value proves nothing.
- Is `freshness?` present where replay matters? Authentication is **injective agreement** (it
  fails on replay as well as forgery), but verdicts are relative to `--sessions` — at the
  default of 2 a pass means no replay within two runs; raise sessions to genuinely stress replay.
- Is `equivalence?` used to confirm both sides derive the same shared secret where that matters?

## C5 — One coherent scenario

- Is the model a single, sensible execution? Verifpal analyzes one scenario per declared peer
  configuration and session; a model trying to cram in mutually exclusive flows is confused.
  Alternate flows should be separate models.
- Do phases (if any) make temporal sense — session in `phase[0]`, compromise/leak in a later
  phase — and are they sequential?
- **Scenario audit:** if the threat model needs corrupt-peer runs (a participant bound to a
  leaked value), are they declared in a `scenarios[ ... ]` block? And conversely — does every
  declared scenario correspond to a *plausible* peer configuration, or does one invent a peer
  the protocol never has?

## C6 — Structural / syntactic soundness

- Public keys via `PUBKEY`, shared secrets via `DH_KEX` — and their argument restrictions
  respected: no public key of a public key, no `DH_KEX` from two public keys, KEM seed fresh.
  Primitive arities correct (AEAD takes a nonce as its 2nd argument; `THRESHOLD_SPLIT[t]`
  carries its threshold); `?` only on the six checkable primitives; every referenced principal
  declared; constants not reassigned or reused across principals (global namespace).
  `verifpal verify` will reject violations — but reading for them explains *why* a model errors.
- Abstraction level: opaque IDs, no attempt to model wire formats or algorithm internals.

## R1 — Results interpreted honestly

- Are clean runs reported as **"no attack found in the bounded search,"** not as proofs? Verifpal
  is a bug-finder, not a prover (verifpal-lang `guidelines/analysis.md`). A model whose author
  reads a clean run as "proven secure" has misread the tool.
- Are reported contradictions understood as **real** attacks (they are — attack-finding is sound)?

## R2 — Honesty note present

- Does the model (or its README) state what it does **not** cover — idealized assumptions,
  single-scenario scope, no unbounded concurrent sessions, no computational attacks? Absence of
  this note is itself a finding: it invites over-trust.

## Reporting

Produce a findings list, most-severe first, each with a `file:line` citation, the defect, and the
concrete consequence (e.g. "line 12: `knows private n` where `n` is a network-wide identifier — if
the attacker knows the network, this over-claims and the `confidentiality? n` pass is spurious;
re-run with `n` public to see the real result"). Prefer showing the tweak that exposes the issue
over asserting it.
