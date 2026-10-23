# Reference models

Five complete, self-contained Verifpal models, bundled so an agent can read a *whole* `.vp`
file end-to-end — not just the inline snippets in `SKILL.md`. They are adapted from the
[Verifpal repository](https://github.com/symbolic-software/verifpal)'s own examples (see
Provenance below) and carry their expected results and teaching commentary in their headers.
They are ordered by complexity; pick the closest structural match to what you are modelling.

| Model | Read it when modelling… | Illustrates |
|---|---|---|
| [`simple.vp`](simple.vp) | the **smallest** teaching model; learning what a man-in-the-middle looks like | unauthenticated Diffie-Hellman (`PUBKEY`/`DH_KEX`), one `AEAD_ENC` message, both queries **fail** (`c1a1`) — the exercise is guarding the keys |
| [`signal.vp`](signal.vp) | a **two-party session** with identity + ephemeral keys, ratcheting, forward secrecy | X3DH `HASH`/`HKDF` key schedule, Double Ratchet, `AEAD_ENC` channel binding, `phase[1]` leak of both identity keys — every query still holds (`c0a0c0a0c0a0`) |
| [`scuttlebutt.vp`](scuttlebutt.vp) | a protocol with a **pre-shared symmetric key** alongside public keys | `MAC`-based channel binding, PSK woven into `HKDF`/`HASH`, identity hiding, replay-style authentication failures (`c1c0c1c0a1a1a1a1a1e1`) |
| [`dp-3t.vp`](dp-3t.vp) | a **multi-party**, time-staged protocol; "what becomes learnable after event X" | 5 principals, a `HASH` ratchet of daily keys, `phase[1]` for a later event, `CONCAT`, an unlinkability payoff query (`c0a1u0` — the failing `a1` is plain-`ENC` upload with no integrity) |
| [`hpke-base.vp`](hpke-base.vp) | **RFC 9180 HPKE** / KEM + key-schedule modeling; an *intentional* authentication failure | `PUBKEY`/`DH_KEX` KEM shape, full `HKDF` key schedule, `AEAD_ENC` with nonce, base mode's lack of sender auth surfaced as `c0a1` |

## How to read a model

Every Verifpal model has the same top-level shape (see the `verifpal-lang` grammar reference):

```
attacker[active|passive]     // 1. threat model
principal Name[ ... ]         // 2. one or more principals declare knowledge + do operations
Sender -> Recipient: values  // 3. messages cross the network ( -> is the ASCII arrow)
phase[n]                      // 4. optional: temporal separation (leaks, forward secrecy)
scenarios[ ... ]              // 5. optional: peer configurations (at most one block)
queries[ ... ]               // 6. the security questions to answer
```

A principal may appear in **several blocks**; Verifpal accumulates its state across them.
Only **constants** may be sent in messages. A `[guarded]` constant can still be read by an
active attacker but not tampered with. A primitive suffixed with `?` is **checked**: the
session aborts at that point if its rewrite fails. Each model's header comment is the best
guide to its own teaching points — read it first.

## Running

```
verifpal verify model.vp                 # full analysis report
verifpal verify model.vp --result-code   # compact code, e.g. c1a1 — compare across runs
verifpal verify model.vp --sessions 1    # stress replay: does a pass at 1 break at 2?
verifpal diagram model.vp                # Mermaid sequence diagram
```

Tweaking a model and re-running is the core Verifpal workflow. Each header suggests the
experiments (guard a key, check a decryption, fix the plain `ENC`); `--result-code` is the
easiest way to compare before and after.

## Validation (verifpal 1.6.7)

All five models parse, sanity-check, and analyze cleanly. Expected result codes, taken from
each file's `Expected:` header (dp-3t states it in its narrative header) and confirmed by
running `verifpal verify <model>.vp --result-code --quiet | tail -1`:

| Model | Result code | Meaning |
|---|---|---|
| `simple.vp` | `c1a1` (at one session and at two) | both queries broken — the unauthenticated-DH man-in-the-middle, on purpose |
| `signal.vp` | `c0a0c0a0c0a0` (at one and at two) | all six queries hold, including after the phase-1 identity-key leak — forward secrecy demonstrated |
| `scuttlebutt.vp` | `c1c0c1c0a1a1a1a1a1e1` (at one and at two) | confidentiality holds, all authentication fails (cross-session replay), equivalence fails |
| `dp-3t.vp` | `c0a1u0` | day-0 pseudonym confidential, plain-`ENC` upload not authenticated (the model's deliberate weakness), unlinkability holds |
| `hpke-base.vp` | `c0a1` (at one and at two) | confidentiality holds; authentication fails — HPKE base mode has no sender auth, as specified |

The failing queries are teaching points, not transcription errors: the repo's own test suite
pins these codes, and the headers explain each failure (and its fix).

## Provenance and licensing

The five models are adapted from the Verifpal repository's `examples/` directory
(`examples/simple.vp`, `examples/messaging/{signal,scuttlebutt}.vp`,
`examples/contact-tracing/lc-dp-3t.vp`, `examples/hpke/hpke_base.vp`), © 2019-2026 Nadim
Kobeissi, licensed **GPL-3.0-only** — the `SPDX-FileCopyrightText` and
`SPDX-License-Identifier` headers in each file are retained verbatim and the model content
is byte-identical to the source (only file names differ). The rest of this kit is MIT
(see the root [LICENSE](../../LICENSE)); **this directory is mixed-licensed** — the example
`.vp` files are GPL-3.0-only, everything else MIT.
