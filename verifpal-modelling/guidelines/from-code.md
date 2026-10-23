# Intake: from source code (an implementation)

The user has a working implementation (Rust, Go, TypeScript, C, …) and wants a Verifpal model of
the protocol it speaks. The challenge is **lifting**: separating the protocol's cryptographic
structure (what belongs in the model) from implementation detail (what must be abstracted away),
without importing the code's bugs or omissions into the model — and without assuming the code is
correct.

## What to keep vs. abstract

| Keep (model it) | Abstract (leave out) |
|---|---|
| Which key/nonce/secret each party holds and where it comes from | Serialization, wire formats, byte layouts, length prefixes |
| The cryptographic operation on each value (encrypt, sign, KDF, MAC) | The concrete algorithm/curve/mode (AES-GCM vs ChaCha — both are `AEAD_ENC`) |
| What is mixed into each derived key (the KDF inputs / transcript) | Buffer management, memory zeroing, allocation |
| Message order and direction on the network | Retries, timeouts, reconnection, framing |
| Which checks the code performs before proceeding (signature/MAC/tag verification) | Error-message text, logging, metrics |
| Whether a key is long-term or per-connection ephemeral | Threading, async plumbing, state machines' internal bookkeeping |

Verifpal is symbolic — key length, cipher mode, and RNG quality are *not* modelled. If a suspected
weakness is computational (padding oracle, timing, weak randomness), say so: it's outside
Verifpal's scope (verifpal-lang `guidelines/analysis.md`).

## Extraction procedure

1. **Find the crypto call sites.** Grep for the crypto library's encrypt/decrypt/sign/verify/KDF/
   MAC calls. Each is a candidate assignment in some principal's block. (If codegraph or another
   index is available, use it to trace which functions produce and consume each key.)
2. **Attribute each value to a principal.** Which party (client/server, initiator/responder)
   computes it, and from what inputs? That fixes which `principal[ ]` block the assignment lands
   in and what that principal must `knows`/`generates` first.
3. **Classify key material honestly.** Long-term identity keys → `knows private` + published
   `PUBKEY(k)`. Per-connection ephemerals → `generates`. Anything hardcoded/embedded → be
   skeptical of `private` (see the "Are you sure it's private?" caution); if the code ships the
   secret in the binary, it may not be private at all. If the code's crypto is deliberately
   weaker than ideal (a forgeable tag, a tamperable ciphertext, a leaky hash), model that with a
   **weakening assumption** (`[forgeable]`, `[malleable]`, `[weak]`) — not by inventing a
   primitive.
4. **Read the message boundary.** Where the code writes to / reads from the socket is a
   `Sender -> Recipient` line. Only the constants crossing there go in the message.
5. **Capture the checks.** Every place the code *verifies before continuing* (checks a tag, a
   signature, a MAC, and errors out on failure) becomes a **checked** primitive (`?`). Crucially:
   if the code **skips** a check (accepts without verifying), model it **unchecked** — that
   faithfully represents the implementation and may be exactly the bug. Do not "fix" the code's
   omission in the model.

   A **nonce-reuse bug in the code** is directly expressible: `AEAD_ENC` takes the nonce as
   its second argument, so model two encryptions under the same key and the same `nonce` value
   with differing plaintext or `ad` — the reuse attack (learn the other plaintext, forge under
   that key+nonce) appears in the analysis automatically. (Conversely, a *correctly* unique
   nonce is a `generates` value fed into each call.)
6. **Locate pre-authentication.** If the code pins or pre-loads a peer's public key (certificate
   pinning, a trusted-keys file), that value is **guarded** on the wire. If it accepts whatever
   arrives, leave it **unguarded**.
7. **Derive the security goals** from what the code is *trying* to protect (the payloads it
   encrypts, the identities it signs). Turn those into queries.

## Don't trust the code — test it

The point of modelling from code is often to find where the implementation's structure is
insecure. So:

- Model what the code **actually does**, checks-skipped and guards-absent included — not the
  idealized protocol the code was supposed to implement.
- Then run the spine's tweak loop (Step 8) to see whether adding the missing check or guard would
  have prevented an attack Verifpal finds. That difference is the actionable finding for the
  developer.
- **Never** silently strengthen the model to match the protocol's intent. If the model and the
  code disagree with the protocol, report all three.

Hand off to the spine (Steps 2–9). The deliverable maps model findings back to specific call sites
/ files in the implementation, and states clearly which are real logical attacks vs. out-of-scope
computational concerns.
