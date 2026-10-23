# Intake: from a requirements / spec document

The user has a written protocol description — an RFC, an academic paper, a design doc, a
whitepaper. The source is authoritative; your job is to extract a faithful model from it, not to
redesign. The risk here is **transcription drift** (subtly changing what the doc says) and
**over-claiming** (reading a stated assumption as a Verifpal `private` when the doc doesn't
guarantee it).

## Extraction checklist

Read the document and pull out, with a page/section citation for each:

1. **Adversary model.** What attacker does the doc assume (Dolev-Yao on-path? honest-but-curious?
   a PKI?)? Map to `attacker[active]` (default) or `passive`. Note anything Verifpal can't express
   (unbounded concurrent sessions, computational assumptions) as an out-of-scope limitation.
2. **Principals & long-term setup.** Every party and its key material. Distinguish carefully:
   - values the doc says are **public** (published keys, parameters) → `knows public`
   - values **pre-shared / pre-authenticated** (a PSK, a pre-known public key) → `knows private`
     and/or a **guarded** constant on the wire — and flag whether the doc actually justifies the
     secrecy (Scuttlebutt's network identifier `n` is the cautionary example: "known to all users
     yet unknown to the attacker" is a strong, debatable claim).
   - values **generated per session** (ephemeral keys, nonces) → `generates`
3. **The message sequence.** Transcribe the doc's message flow verbatim into `Sender -> Recipient`
   lines. Pick **one** concrete run if the doc describes variants (0-RTT vs full handshake, with/
   without a resumption ticket) — model each variant separately.
4. **Cryptographic operations.** Map each computation to a built-in primitive. Key derivation
   chains (HKDF ladders, transcript hashes) → `HKDF`/`HASH`; AEAD with a transcript as associated
   data → `AEAD_ENC(k, nonce, m, ad)`; signatures over a transcript → `SIGN`/`SIGNVERIF`
   (under `PUBKEY(key)`). Preserve the *structure* (what's mixed into each key) even while
   abstracting the concrete algorithm.
5. **Stated security goals.** The doc's claimed properties (confidentiality, mutual auth, forward
   secrecy, identity hiding, KCI resistance, replay resistance) → the queries. This is the
   highest-value extraction: you are checking the doc's *own claims*.

## Prioritizing when the doc claims many properties

A rich spec may claim a dozen properties. If you must prioritize which to model/query first, score
each by **impact** (High: a break is catastrophic — message confidentiality, peer authentication;
Medium: degrades but doesn't collapse — identity hiding, forward secrecy; Low: nice-to-have).
Model the High goals first, get a clean baseline, then add Medium/Low and the tweak experiments
that stress them.

## Faithfulness rules

- **Cite as you go.** Every guard, every `private`, every check should trace to a sentence in the
  doc. If you can't cite it, you're assuming — flag it.
- **Don't strengthen the protocol.** If the doc doesn't sign a value, don't add a `SIGN`. If it
  doesn't say a key is pre-authenticated, don't guard it in the baseline — model the unguarded
  case and *report* that guarding would be needed.
- **Model the doc, then stress it.** Baseline = the protocol as written. Then use spine Step 8 to
  test what happens when a stated assumption fails (unguard the "pre-authenticated" key, make the
  "secret" PSK public) — that reveals what the protocol's security actually rests on.

Hand off to the spine (Steps 2–9). The deliverable pairs each of the doc's claimed properties with
a Verifpal result and the assumptions that result depends on.
