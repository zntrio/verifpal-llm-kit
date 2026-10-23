# Verifpal LLM Kit

Agent skills for using [Verifpal](https://verifpal.com) — cryptographic protocol verification in
the symbolic (Dolev-Yao) model — with LLM agents.

Three standalone skills teach an agent Verifpal end to end: language and CLI reference, protocol
modelling and analysis, and implementing code against a verified model.

Adapted from [quint-co/quint-llm-kit](https://github.com/quint-co/quint-llm-kit) (Apache-2.0),
covering Quint → Verifpal.

## Skills

| Skill | What it does |
|---|---|
| [`verifpal-lang`](verifpal-lang/SKILL.md) | Verifpal language and CLI reference — syntax (attacker, principals, constants, primitives, equations, messages, phases, queries), built-in cryptographic primitives and equational theory, guarded constants, checked primitives, `verifpal` CLI (verify/pretty), attack output reading |
| [`verifpal-modelling`](verifpal-modelling/SKILL.md) | Model a cryptographic protocol in Verifpal and analyze its security. Builds a `.vp` model from an idea, requirements doc, or source code; walks the modelling flow (attacker, principals, messages, guards, checks, phases, queries); drives the tweak-and-rerun analysis loop. Also audits existing `.vp` models |
| [`verifpal-execute-spec`](verifpal-execute-spec/SKILL.md) | Implement or change code against an existing, verified Verifpal model — Research → Plan → Implement → Verify with the model as ground truth |

## Install

**Any agent (npx)**

```bash
npx skills add zntrio/verifpal-llm-kit
```

Install a single skill:

```bash
npx skills add zntrio/verifpal-llm-kit --skill verifpal-lang
npx skills add zntrio/verifpal-llm-kit --skill verifpal-modelling
npx skills add zntrio/verifpal-llm-kit --skill verifpal-execute-spec
```

## Prerequisites

The skills drive the `verifpal` CLI. Install Verifpal ≥ 0.40 from
[verifpal.com](https://verifpal.com) (Homebrew on Linux/macOS, Scoop on Windows) and make sure
`verifpal` is on your `PATH`.

## Usage

- "Model this handshake in Verifpal" → verifpal-modelling
- "Does this protocol have forward secrecy" → verifpal-modelling
- "Review my Verifpal model" → verifpal-modelling (review flow)
- "What are the arguments to `HKDF`" → verifpal-lang
- "Fix this parse error in my `.vp` file" → verifpal-lang
- "Implement this verified model in Rust" → verifpal-execute-spec

Four complete, analyzable example models ship in
[`verifpal-modelling/examples/`](verifpal-modelling/examples/) — challenge-response, Signal,
Scuttlebutt, DP-3T — ordered by complexity.

## License

MIT — see [LICENSE](LICENSE). Adapted from
[quint-co/quint-llm-kit](https://github.com/quint-co/quint-llm-kit) (Apache-2.0).
