---
name: verifpal-execute-spec
description: >
  Implement or change code against an existing, verified Verifpal (`.vp`) model. Uses a
  Research -> Plan -> Implement -> Verify workflow grounded by the model as the source of truth for
  the protocol's cryptographic structure. Use when the user wants to refactor a protocol
  implementation, add a feature, or close a gap between code and a Verifpal model — with the `.vp`
  model as the formal constraint every change must keep satisfying. If no model exists yet, use
  verifpal-modelling first to build the grounding artifact. For Verifpal syntax/primitives/CLI, see
  verifpal-lang.
---

# Execute the Verifpal model

When you have a verified Verifpal model and want to change the code that implements the protocol,
this skill grounds the work in the model. The `.vp` model is not advisory — it is the analyzed
statement of the protocol's cryptographic structure and the security results (which queries hold,
which attacks exist and under what conditions). All code changes must keep the model's intended
results intact. The model is reviewed first; the code follows.

## When to use

- **Refactor** — restructure the implementation while preserving protocol behavior (model fixed;
  code must still match it).
- **New feature** — add functionality described by or consistent with the model.
- **Gap closure** — the code has drifted from the model (a check skipped, a key mixed differently);
  bring it back into alignment.
- **Model-first change** — the protocol is intentionally changing; update and re-verify the model
  first, then implement.

If no `.vp` model exists yet, use **verifpal-modelling** to create it first.

---

## Core principle: the model is ground truth

The model states what the protocol must cryptographically do: which values are guarded
(pre-authenticated), which primitives are checked (validated before proceeding), what is mixed
into each derived key, and which security queries must hold. The code must implement *that*.

**Never edit the model to make a failing result pass.** If the protocol behavior is intentionally
changing, stop and present the proposed model change to the user *before* touching code — the
model change is the highest-leverage review point. A model tweaked to match broken code is worse
than no model.

Remember Verifpal's boundary (verifpal-lang `guidelines/analysis.md`): a clean model run means "no
attack found in the bounded search," not a proof, and computational issues (timing, padding,
RNG) are out of scope. The model constrains *protocol structure*; it does not certify the crypto
implementation.

---

## Workflow

```
[Verifpal model] + [desired change]
        |
  Phase 0: Orient — read the model: what does it guarantee? is this a code change or a model change?
        |
  Phase 1: Research (compact) — map the gap between model and code (target < 300 lines)
        |
  Phase 2: Plan — precise steps; per step, how re-verification confirms the model still holds
        |
  Phase 3: Implement — one step at a time; re-run verifpal after substantive edits
        |
  Phase 4: Verify — re-run the model; results must match the documented intended results
```

---

## Phase 0: Orient

1. **Read the model.** Which principals, guards, checks, phases? Which queries, and what is each
   query's *intended* result — clean, or a documented expected attack under a named condition?
2. **Read the handoff note** (the model's README / comment block, per verifpal-modelling Step 9):
   which source files correspond to which principals/operations, and which assumptions the results
   depend on.
3. **Classify the change.** Refactor (nothing observable changes)? Feature (new operation/message)?
   Gap closure (code diverged)? And critically: **does this change the protocol, or only the
   code?** A protocol change means the model changes first (see Model-change protocol below).

**Lightweight path:** for a small change (one function, no new key material, no new message, no
change to a guard/check), skip Phase 1 and go to Phase 2.

---

## Phase 1: Research (compact)

For non-trivial changes, produce a compact gap analysis. Do not read the whole codebase — target a
focused summary under ~300 lines. Answer:

1. For each **principal** in the model, where is its state/keys managed in code?
2. For each **assignment** (primitive/equation) in the model, which function(s) perform it?
3. For each **checked** primitive (`?`) and **guarded** constant (`[ ]`) in the model, where does
   the code enforce the corresponding validation / pinning? (Missing enforcement is a live gap.)
4. Which model behaviors have **no** code counterpart (gaps)? Which code behaviors are **not** in
   the model (out of scope, or model incompleteness)?
5. For the requested change, which source files and which model elements are affected?

If the analysis missed something critical, do one targeted follow-up read before planning.

---

## Phase 2: Plan

A precise plan. Each step names the file/function, the behavior delta, and the re-verification
gate. Present it to the user before implementing — plan review beats code review.

```markdown
## Change: [one sentence]

### Model impact
- Queries/results that must stay unchanged: [list]
- Guards/checks that must stay enforced: [list]
- Results that will change (if any): [list] — REQUIRES A MODEL CHANGE + USER APPROVAL FIRST

### Steps
#### Step 1: [file] — [what changes]
- Behavior delta: [...]
- Verification gate: `verifpal verify model.vp` — [which query result confirms this step]

### Rollback
If re-verification shows a NEW contradiction (or loses an intended one) after step N, stop and
return to planning. Do not proceed and do not weaken the model.
```

If the plan requires changing the model, follow the **Model-change protocol** and get approval
first.

---

## Phase 3: Implement

Follow the plan. After each substantive edit:

1. If the model was touched, run `verifpal verify model.vp` and confirm it parses/sanity-checks.
2. Make the code change.
3. Re-run the code's own tests **and** `verifpal verify model.vp`. Confirm the query results still
   match the documented intended results (no new contradiction; no intended attack silently gone).
4. If a gate fails: **stop, diagnose, return to Phase 2.** Do not fix by loosening the model.

The most important code-level checks to keep faithful to the model:

| Model element | The code must… |
|---|---|
| A **checked** primitive (`?`) | actually verify (tag/signature/MAC) and abort on failure — not accept-and-continue. |
| A **guarded** constant (`[ ]`) | pin / pre-authenticate that value (cert pinning, trusted key), not accept whatever arrives. |
| A key derivation assignment | mix exactly the inputs the model mixes into that key — no more, no less. |
| A `generates` value | be freshly random per session, never reused/static. |
| A `knows private` value | genuinely stay secret in the implementation (not shipped in the binary). |

---

## Phase 4: Verify

Re-run the full model and confirm results against intent:

- **Every query the model expects to be clean is still clean.** A new `Result` contradiction means
  the change introduced a protocol weakness — return to Phase 2.
- **Every documented expected attack is still reported under its stated condition.** If an
  intended contradiction *disappeared*, the change altered protocol behavior (possibly fine, but it
  is a model change — get it approved and update the note).
- Read any new `Result` trace step by step; a `G^nil` in it is a man-in-the-middle fingerprint.

If results diverge from intent and the model itself is genuinely wrong, present the proposed model
change to the user — do not just edit it.

---

## Model-change protocol

When the change intentionally alters the protocol (new guarded/unguarded value, changed check,
new message, different key schedule):

1. **Draft the model change** and show the diff to the user *before* any code change.
2. **Re-verify the updated model in isolation** — parse, sanity-check, run all queries; confirm the
   new intended results and update the honesty note.
3. **Get explicit approval** — do not touch code until the model change is approved.
4. Then implement the code to satisfy the updated model.

This keeps the model as source of truth even as it evolves.

---

## What NOT to do

| Anti-pattern | Why it breaks the workflow |
|---|---|
| Edit the model to silence a new contradiction | Destroys the model as ground truth. |
| Skip `verifpal verify` between steps | Bugs compound; you lose the link between a step and its result. |
| Implement a "check" as accept-without-verifying while the model has `?` | Code and model disagree; the model's authentication result is now a lie about the code. |
| Accept a wire value the model **guards** | Silently reintroduces the man-in-the-middle the guard was modelling. |
| Read a clean model run as "proven secure" | Verifpal is a bounded bug-finder, not a prover. |
| Treat the model as documentation | It is a machine-checkable constraint on protocol structure. |

---

## Lightweight path for simple changes

For a small, well-understood change (one function, no new key material, message, guard, or check):

1. Read the relevant principal block in the model.
2. Identify which query result(s) cover the changed behavior.
3. Make the change.
4. Run `verifpal verify model.vp` and confirm those results are unchanged; run the code tests.
5. Done. (Skip Phases 0–1; use 2–4 only for non-trivial changes.)
