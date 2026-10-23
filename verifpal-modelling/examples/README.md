# Reference models

Four complete, self-contained Verifpal models, bundled so an agent can read a *whole*
`.vp` file end-to-end — not just the inline snippets in `SKILL.md`. Each is transcribed
from the Verifpal User Manual (Nadim Kobeissi, First Edition) and lightly commented with
a teaching banner. They are ordered by complexity; pick the closest structural match to
what you are modelling.

| Model | Read it when modelling… | Illustrates |
|---|---|---|
| [`challenge-response.vp`](challenge-response.vp) | the **smallest** proof-of-possession / nonce exchange; learning the core defenses | CHECKED primitives (`?`), GUARDED constants (`[ ]`), `SIGN`/`SIGNVERIF`, a fresh `nonce` (manual §3.5) |
| [`signal.vp`](signal.vp) | a **two-party session** with identity + ephemeral keys, ratcheting, forward secrecy | X3DH `HASH`/`HKDF` key schedule, `AEAD_ENC` channel binding, guarded long-term keys, `phase[1]` key leak (manual ch. 5) |
| [`scuttlebutt.vp`](scuttlebutt.vp) | a protocol with a **pre-shared symmetric key** alongside public keys | `MAC`-based channel binding, PSK woven into `HKDF`/`HASH`, identity hiding, `ASSERT` checks (manual ch. 6) |
| [`dp-3t.vp`](dp-3t.vp) | a **multi-party**, time-staged protocol; "what becomes learnable after event X" | 5 principals, a `HASH` ratchet of daily keys, `phase[1]` for a later event, `CONCAT` (manual ch. 7) |

## How to read a model

Every Verifpal model has the same top-level shape (see `../guidelines/` and the
`verifpal-lang` grammar reference):

```
attacker[active|passive]     // 1. threat model
principal Name[ ... ]         // 2. one or more principals declare knowledge + do operations
Sender -> Recipient: values  // 3. messages cross the network ( -> is the ASCII arrow)
phase[n]                      // 4. optional: temporal separation (leaks, forward secrecy)
queries[ ... ]               // 5. the security questions to answer
```

A principal may appear in **several blocks**; Verifpal accumulates its state across them.
Only **constants** may be sent in messages. A `[guarded]` constant can still be read by an
active attacker but not tampered with. A primitive suffixed with `?` is **checked**: the
session aborts at that point if its rewrite fails.

## Running

```
verifpal verify signal.vp
```

Each banner lists **experiments** — small edits (remove a `?`, drop a `[ ]` guard, make a
constant `public`, add a `phase`) that flip a secure result into an attack. Tweaking a
model and re-running is the core Verifpal workflow; the banners tell you what to expect.

## Validation (verifpal 0.52.0)

All four models parse, sanity-check, and analyze cleanly (no syntax/arity/sanity errors). Query
results observed with `verifpal verify`:

| Model | Result under verifpal 0.52.0 |
|---|---|
| `challenge-response.vp` | **All queries PASS** — matches the manual exactly (checked `SIGNVERIF` + guarded `gs` defeat the MITM). |
| `dp-3t.vp` | **Matches the manual exactly.** `EphID02A` stays confidential (PASS); `EphID1xA`/`EphID2xA` are recoverable after the phase-1 diagnosis (reported as contradictions — this is the *intended* outcome per manual §7.3); `m2` authenticated (PASS). |
| `signal.vp` | Confidentiality of `m1`/`m2`/`m3` PASS (incl. after the phase-1 long-term-key leak → **forward secrecy holds**); `authentication? e2`/`e3` PASS; `authentication? e1` reported as a contradiction. |
| `scuttlebutt.vp` | Confidentiality of `m1`/`m2`/`longTermAPub` PASS (**initiator identity hiding holds**, `n` acting as a PSK); the five `authentication?` queries reported as contradictions (cross-session replay). |

### Divergence from the manual's narrative

For **Signal** and **Scuttlebutt**, the manual's prose reports the fully-guarded/checked model as
finding *no* contradictions at all, including for authentication. Under **verifpal 0.52.0** the
confidentiality/forward-secrecy story reproduces exactly, but several **authentication** queries
are reported as contradictions, reached by **cross-session replay** ("In another session:" in the
attack trace).

This is a genuine engine-behavior difference, not a transcription error (the models are faithful
to the manual's listings; the only intentional change is adding `?` to Signal's message
`AEAD_DEC`s — without them *every* Signal message authentication breaks, and checking received
decryptions is the correct way to model authentication anyway). The manual's own **Notes** record
a Chapter-4 "engine redesign" (Print 18) that replaced the analysis methodology; its worked
result text predates that redesign. The divergence is itself a teaching point the skills make
explicitly: Verifpal authentication is **non-injective** and the active attacker runs an
**unbounded number of sessions** reusing non-fresh values, so replay-style authentication
contradictions are expected (verifpal-lang `guidelines/queries.md` and `guidelines/analysis.md`).
Treat every result as "what this engine version finds for this scenario," never as a proof.

## A note on syntax vs. the manual

The manual pretty-prints messages with the Unicode arrow `→`. These files use the ASCII
`->`, which is what the Verifpal parser expects in source. `//` begins a comment.

## Provenance

Transcribed from the *Verifpal User Manual*, First Edition (Print 19, 2026),
CC BY-NC-ND 4.0. The Verifpal software itself is GPLv3. See https://verifpal.com.
`challenge-response.vp` is the manual's §3.5 model **with** the two fixes the text asks
the reader to find (checked `SIGNVERIF`, guarded `gs`).
