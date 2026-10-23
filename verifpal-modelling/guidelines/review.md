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
- Every `knows password`: is it run through `PW_HASH` before being used as key material? A raw
  password used directly in `ENC`/`AEAD_ENC` with attacker-known siblings is offline-recoverable
  (verifpal-lang `guidelines/analysis.md`, password extraction).
- A model that marks too much `private` produces a falsely-secure result. This is the most common
  and most dangerous defect.

## C2 — Deliberate guards

- Every guarded `[c]`: is pre-authentication of that value *realistic*? Guarding all public keys
  often models a world that doesn't exist (keys are rarely tamper-proof on the wire).
- Is there an **unguarded** counterpart run? A model that only ever guards keys hides the
  man-in-the-middle it should be surfacing. A proper audit analyzes both.
- Conversely, a value the protocol genuinely pre-authenticates but the model left unguarded may
  produce a spurious attack.

## C3 — Deliberate checks

- Every checkable primitive (`AEAD_DEC`, `SIGNVERIF`, `ASSERT`, `SPLIT`, …): is it `?`-checked
  where the real protocol validates, and left unchecked where the real protocol (or the code
  being modelled) skips validation?
- **Authentication queries require checks.** If the model queries `authentication?` on a value the
  recipient never uses in a *checked* primitive, the passing result is vacuous — call it out.

## C4 — Queries match the stated goals

- Does every security goal the model claims to test have a corresponding query? Missing queries =
  untested claims.
- Are authentication queries targeting values the recipient actually **uses in a primitive**
  (verifpal-lang `guidelines/queries.md`)? A query on a received-but-unused value proves nothing.
- Is `freshness?` present where replay matters? Authentication is non-injective and does not rule
  out replay on its own.
- Is `equivalence?` used to confirm both sides derive the same shared secret where that matters?

## C5 — One coherent scenario

- Is the model a single, sensible execution? Verifpal analyzes one scenario; a model trying to
  cram in mutually exclusive flows is confused. Alternate flows should be separate models.
- Do phases (if any) make temporal sense — session in `phase[0]`, compromise/leak in a later
  phase — and are they sequential?

## C6 — Structural / syntactic soundness

- Equations rooted at `G`; primitive arities correct; `?` only on checkable primitives; every
  referenced principal declared; constants not reassigned or reused across principals (global
  namespace). `verifpal verify` will reject violations — but reading for them explains *why* a
  model errors.
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
