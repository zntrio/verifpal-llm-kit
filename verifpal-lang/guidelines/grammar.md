# Verifpal grammar and sanity rules

The complete BNF grammar of the Verifpal language, from the manual's appendix (Figure 1). In
source, the message arrow is the ASCII `->` (the manual pretty-prints it as `→`), and `//` begins
a comment.

## BNF

```
<model>              ::= <attacker> <principal> (<principal> | <message> | <phase>)+ <queries>

<attacker>           ::= 'attacker[' ('active' | 'passive') ']'

<principal>          ::= 'principal' <string> '[' (<knows> | <generates> | <leaks> | <assignment>)+ ']'

<knows>              ::= 'knows' ('private' | 'public' | 'password') <constant> (',' <constant>)*
<generates>          ::= 'generates' <constant> (',' <constant>)*
<leaks>              ::= 'leaks' <constant> (',' <constant>)*
<assignment>         ::= <constant> (',' <constant>)* '=' (<primitive> | <equation>)

<message>            ::= <string> '->' <string> ':' (<constant> | <guardedConstant>)
                                                    (',' (<constant> | <guardedConstant>))*

<phase>              ::= 'phase[' <number> ']'

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

<constant>           ::= <string>
<guardedConstant>    ::= '[' <constant> ']'

<primitive>          ::= <primitiveName> '(' (<constant> | <primitive> | <equation>)
                                             (',' (<constant> | <primitive> | <equation>))* ')' ['?']
<equation>           ::= <constant> '^' <constant>

<primitiveName>      ::= 'BLIND' | 'UNBLIND' | 'RINGSIGN' | 'RINGSIGNVERIF' | 'PW_HASH' | 'HASH'
                       | 'HKDF' | 'AEAD_ENC' | 'AEAD_DEC' | 'ENC' | 'DEC' | 'MAC' | 'ASSERT'
                       | 'CONCAT' | 'SPLIT' | 'SIGN' | 'SIGNVERIF' | 'PKE_ENC' | 'PKE_DEC'
                       | 'SHAMIR_SPLIT' | 'SHAMIR_JOIN'
```

## Structural facts the grammar encodes

- A model is exactly: **one** `attacker`, then **at least one** `principal`, then any mix of
  further principals / messages / phases, then **one** `queries` block. Order matters — attacker
  first, queries last.
- **Guarded constants** (`[c]`) appear only inside messages, never in a principal block or an
  assignment.
- The `?` (checked) suffix attaches to a **primitive** occurrence, not to constants or equations.
- An **equation** is `constant ^ constant`; chain via assignment (`gxy = gx^y`) to raise to
  multiple exponents. All equations are rooted at the reserved generator `G`.
- Only **constants** (guarded or not) may be sent in messages — never a bare primitive or equation.
- A `precondition` query option wraps a full `<message>`.

## Sanity-check rules (enforced after parsing, before analysis)

Beyond grammar, Verifpal validates:

- **Phases are sequential** — `phase[0]`, `phase[1]`, `phase[2]`, … with no gaps or reordering.
- **All referenced principals are declared** — every principal named in a message or query exists.
- **Primitive arities match** their specification (e.g. `HKDF` takes 3 inputs; `HASH` 1–5).
- **`?` only on checkable primitives** — `ASSERT`, `SPLIT`, `AEAD_DEC`, `SIGNVERIF`,
  `RINGSIGNVERIF` (and the other rewrite-bearing primitives). Applying `?` elsewhere is an error.
- **DH equations use `G` as root generator** — every equation ultimately rooted at `G`.
- **`SPLIT` input must be a `CONCAT`** — otherwise Verifpal errors.

Constant rules (from the language, enforced during construction): immutability (no reassignment),
global namespace (no name reused across principals, even privately), no referencing (a constant
may be assigned only to a primitive or equation, never to another constant).
