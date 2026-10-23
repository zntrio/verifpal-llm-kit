# Verifpal grammar and sanity rules

The complete BNF grammar of the Verifpal language, derived line-for-line from the 1.6.7 parser.
In source, the message arrow is the ASCII `->` (the formatter pretty-prints it as `→`), `//`
begins a comment, and block comments are also supported (an unterminated block comment is an
error).

## BNF

```
<model>              ::= <attacker> (<principal> | <message> | <phase>)+ <scenarios>? <queries>

<attacker>           ::= 'attacker[' ('active' | 'passive') ']'

<principal>          ::= 'principal' <string> '[' (<knows> | <generates> | <leaks> | <assignment>)+ ']'

<knows>              ::= 'knows' ('private' | 'public') <constant> (',' <constant>)*
<generates>          ::= 'generates' <constant> (',' <constant>)*
<leaks>              ::= 'leaks' <constant> (',' <constant>)*
<assignment>         ::= <constant> (',' <constant>)* '=' <primitive>

<message>            ::= <string> '->' <string> ':' (<constant> | <guardedConstant>)
                                                    (',' (<constant> | <guardedConstant>))*

<phase>              ::= 'phase[' <number> ']'

<scenarios>          ::= 'scenarios[' <scenario>+ ']'
<scenario>           ::= <string> '[' <constant> '=' <constant> (',' <constant> '=' <constant>)* ']'

<queries>            ::= 'queries[' (<confidentialityQuery> | <authenticationQuery>
                                     | <freshnessQuery> | <unlinkabilityQuery>
                                     | <equivalenceQuery>)* ']'

<confidentialityQuery> ::= 'confidentiality?' <constant> <queryOptions>?
<authenticationQuery>  ::= 'authentication?' <string> '->' <string> ':' <constant> <queryOptions>?
<freshnessQuery>       ::= 'freshness?' <constant> <queryOptions>?
<unlinkabilityQuery>   ::= 'unlinkability?' <constant> ',' <constant> (',' <constant>)* <queryOptions>?
<equivalenceQuery>     ::= 'equivalence?' <constant> ',' <constant> (',' <constant>)* <queryOptions>?

<queryOptions>       ::= '[' <queryOption>* ']'
<queryOption>        ::= 'precondition' '[' <message> ']'

<constant>           ::= <string> | '_'        // '_' only on the left of an assignment
<guardedConstant>    ::= '[' <constant> ']'

<primitive>          ::= <primitiveName> ('[' (<threshold> | <capability> (',' <capability>)*) ']')?
                         '(' <value> (',' <value>)* ')' ['?']
<threshold>          ::= <number>
<capability>         ::= ('weak' | 'forgeable' | 'malleable') ('from phase' <number>)?
<value>              ::= <constant> | <primitive>

<primitiveName>      ::= 'ASSERT' | 'CONCAT' | 'SPLIT' | 'HASH' | 'HKDF' | 'AEAD_ENC' | 'AEAD_DEC'
                       | 'ENC' | 'DEC' | 'MAC' | 'PUBKEY' | 'DH_KEX' | 'SIGN' | 'SIGNVERIF'
                       | 'PKE_ENC' | 'PKE_DEC' | 'THRESHOLD_SPLIT' | 'THRESHOLD_JOIN'
                       | 'THRESHOLD_SIGN' | 'RINGSIGN' | 'RINGSIGNVERIF' | 'BLIND' | 'UNBLIND'
                       | 'KEM_ENCAP' | 'KEM_DECAP'
```

Notes on the grammar:

- **No equations.** The old `<equation> ::= <constant> '^' <constant>` and the reserved generator
  `G` are gone; public keys and DH shared secrets are ordinary primitive applications
  (`PUBKEY`, `DH_KEX`).
- The bracket on a primitive carries **either** a threshold (only `THRESHOLD_SPLIT`: written
  `THRESHOLD_SPLIT[2](k)`) **or** one or more weakening capabilities
  (`AEAD_ENC[forgeable](…)`, `HASH[weak from phase 1](…)`), never both kinds mixed on one
  primitive.
- A `<scenario>`'s leading `<string>` is a **principal name** (title-cased like any principal),
  followed by a bracketed list of `constant = constant` bindings — e.g.
  `Alice[gpeer = gb]`.
- Principals may be declared in **multiple blocks**; the blocks run in the order they appear and
  state accumulates.

## Structural facts the grammar encodes

- A model is exactly: **one** `attacker` (first statement), then **at least one** principal
  block / message / phase (at least one principal must be declared), then an **optional,
  at-most-one** `scenarios` block, then the `queries` block, **last**. Order matters.
- `queries` closes the model: anything after it is a **hard error** (rejected, not ignored — a
  principal written there would silently never be analyzed). The `scenarios` block must come
  **directly before** `queries`; a second `scenarios` block is an error.
- The `queries` block may be **empty only when scenarios are declared**; otherwise a model must
  ask at least one question.
- **Guarded constants** (`[c]`) appear only inside messages, never in a principal block or an
  assignment.
- The `?` (checked) suffix attaches to a **primitive** occurrence, not to constants.
- `_` (anonymous constant) may only name the **output of an assignment** — never in a
  `knows`/`generates`/`leaks` declaration, a message, or a query. It desugars to an internal
  `unnamed_N`.
- Only **constants** (guarded or not) may be sent in messages — never a bare primitive.
- The right side of an assignment `=` must be a **primitive**, never a bare constant (renaming a
  value would give it two names and make queries ambiguous).
- A `precondition` query option wraps a full `<message>`.

## Sanity-check rules (enforced after parsing, before analysis)

Beyond grammar, Verifpal validates:

- **Phases are sequential** — `phase[0]`, `phase[1]`, `phase[2]`, … incrementing by exactly one,
  with no gaps or reordering.
- **All referenced principals are declared** — every principal named in a message, query, or
  scenario must be declared (principals are also implicitly declared by appearing in a message).
  Principal names are **title-cased** (`Alice`, `BackendServer`), must not be reserved words, and
  a model may declare at most 128.
- **Primitive arities match** their specification (e.g. `HKDF` takes exactly 3 inputs; `HASH`
  1–5; `AEAD_ENC`/`AEAD_DEC` take 4 including the nonce; `KEM_ENCAP` binds exactly 2 outputs;
  `THRESHOLD_SPLIT` binds 2–16 outputs; `THRESHOLD_JOIN` takes 2–16 arguments).
- **`?` only on the six checkable primitives** — `ASSERT`, `SPLIT`, `AEAD_DEC`, `SIGNVERIF`,
  `RINGSIGNVERIF`, `KEM_DECAP`. Elsewhere it is an error (`DEC`, `PKE_DEC` and `UNBLIND` are no
  longer checkable).
- **Capability brackets are supported by the primitive** — `weak` needs a spec with
  confidentiality to lose, `forgeable` an authenticating secret, `malleable` a vary-able
  ciphertext position (`ENC` only). Unsupported combinations are sanity errors with a suggested
  alternative.
- **`SPLIT` input must be a `CONCAT`** — otherwise Verifpal errors.
- **`THRESHOLD_SPLIT` threshold bounds** — the bracket carries `t` with `2 ≤ t ≤ n`, where `n`
  is the number of bound outputs; a threshold on any other primitive is an error (and
  `THRESHOLD_SPLIT` without one is an error too). `THRESHOLD_JOIN`/`THRESHOLD_SIGN` take no
  threshold.
- **Argument restrictions on key-derivation primitives**:
  - `PUBKEY(x)`: `x` may not be a `PUBKEY` or `DH_KEX` output (a public value has no public key).
  - `DH_KEX(pk, sk)`: `pk` may not be a `DH_KEX` output; `sk` may not be a `PUBKEY` or `DH_KEX`
    output (the attacker cannot compute a shared secret from two public keys).
  - `KEM_ENCAP(pk, r)`: `pk` may not be a `DH_KEX`/`KEM_ENCAP`/`KEM_DECAP` output; `r` may not
    be a `PUBKEY` or `DH_KEX` output.
  - `KEM_DECAP(dk, ct)`: `dk` may not be a `PUBKEY` or `DH_KEX` output.
- **Scenario bindings name declared values** — each `target = value` binding must reference
  constants the model has declared; a scenario binds at least one constant.

Constant rules (from the language, enforced during construction): immutability (no
reassignment), global namespace (no name reused across principals, even privately), no
referencing (a constant may be assigned only to a primitive, never to another constant).

### Reserved words

A constant (or principal) may not be named: any language keyword or primitive name (checked
**case-insensitively**: `attacker`, `passive`, `active`, `principal`, `knows`, `generates`,
`leaks`, `phase`, `public`, `private`, `confidentiality`, `authentication`, `freshness`,
`unlinkability`, `equivalence`, `precondition`, `primitive`, `queries`, `scenarios`, plus every
primitive name), the single letter `g`, anything prefixed `unnamed` (anonymous outputs desugar
to `unnamed_N`), or anything prefixed `attacker`. File names must end `.vp` and be at most 64
characters long.
