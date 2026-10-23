# Intake: from nothing (an idea, built interactively)

The user has a protocol idea but no written spec or code — a sketch in their head, a whiteboard
photo, a "what if Alice and Bob…". Your job in intake is to interview them into a concrete enough
understanding that the **Shared modelling spine** (SKILL.md) can run. Build the model *with* them,
analyzing early so design decisions are validated as they're made.

## Interview order

Ask in this order — each answer constrains the next. Don't ask everything at once; a few sharp
questions, then draft, then refine.

1. **Use case & adversary.** What is this protocol *for*, and who is the attacker? On-path
   (active) is the default; only a genuinely no-active-attacker setting justifies `passive`.
2. **Principals & roles.** Who participates? For each: what do they **know before the session**
   (public? truly private? a weak human password?) and what do they **generate fresh** each run
   (ephemeral keys, nonces)?
3. **The message flow.** Walk one concrete run end to end: who sends what to whom, in order. Draw
   it as `Sender -> Recipient: values`. If the protocol can go several ways, pick **one** run now;
   note the others as future models.
4. **The operations.** For each value a principal computes, which cryptographic operation produces
   it? Map it to a built-in primitive (verifpal-lang primitive table). If they describe something
   with no built-in equivalent, find the closest abstraction — you cannot define new primitives.
5. **Security goals.** For each sensitive value: secret from the attacker? authenticated as coming
   from a specific party? fresh/non-replayable? forward-secret after a later key compromise? These
   become the queries.

## Draft-analyze-refine loop

Don't wait for a complete picture. As soon as you have the attacker + one principal + one message
+ one query, write it and run `verifpal verify`. Then grow the model one principal / one message
at a time, re-running after each. This catches sanity errors early and lets the user *see* a goal
being met or broken as they decide it.

## Surface assumptions out loud

Interactive modelling is where silent wrong assumptions do the most damage. Before drafting, state
back what you're assuming and let them correct you:

```
ASSUMPTIONS:
1. Active attacker (on-path). [passive if you disagree]
2. Alice and Bob have pre-authenticated each other's long-term public keys → I'll GUARD them.
3. `psk` is a genuine pre-shared secret unknown to the attacker → knows private.
4. Goal: confidentiality + authentication of the message; forward secrecy is out of scope for v1.
-> Correct me or I proceed with these.
```

The guard/check/private decisions especially deserve confirmation — they are exactly the knobs
that flip a result, so a wrong assumption produces a confidently wrong answer.

## Hand off to the spine

Once you have use case, principals, one message flow, operations, and goals, proceed through the
spine Steps 2–9. Lean hard on Step 8 (tweak-and-rerun): with an interactively-built model the user
learns most from watching you guard/unguard and check/uncheck and narrating why the result moves.
Deliver the mapping of "configuration → which goals hold," plus the honesty note.
