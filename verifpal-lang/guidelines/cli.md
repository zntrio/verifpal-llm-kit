# CLI and tooling

Verifpal 1.6.7 is a command-line application for Windows, Linux, macOS and FreeBSD — free and
open-source (GPLv3), a single binary with no separate install step. Get it from
https://verifpal.com (Homebrew `brew install verifpal`; Scoop on Windows; Homebrew/Linux packages
place shell completions automatically).

## Commands

Run `verifpal` with no arguments to print the version and available options.

| Command | Purpose |
|---|---|
| `verifpal verify MODELS... [flags]` | Parse, sanity-check, expand scenarios/sessions, and analyze; print query verdicts. The main command. Analyzes several models independently. |
| `verifpal pretty MODELS... [--write\|-w] [--check]` | Reformat models into the canonical Verifpal style. Prints to stdout by default; `--write` edits files in place; `--check` reports (without modifying) which files are not canonically formatted. |
| `verifpal diagram MODEL` | Print a **Mermaid sequence diagram** of the model to stdout (paste into the Mermaid live editor). Takes exactly one model. For a rendered diagram together with the attacks, use `verify --format html`. |
| `verifpal about` | Print the version banner, homepage, author. Takes no options. |
| `verifpal lsp [--stdio]` | Run the Verifpal language server over stdio (LSP). `--stdio` is accepted and ignored — stdio is the only transport. Not meant to be run by hand. |
| `verifpal completion SHELL` | Print a shell completion script (bash, elvish, fish, powershell, zsh). |
| `verifpal man` | (hidden) Print the roff source of the `verifpal(1)` manual page. |

### verify flags

| Flag | Purpose |
|---|---|
| `--result-code` | Print the verdicts as a compact **result code** and suppress the banner: one letter + one digit per query, in model order — `c`/`a`/`f`/`u`/`e` for confidentiality/authentication/freshness/unlinkability/equivalence, each followed by `0` (holds) or `1` (broken). `c1a0` = first query (confidentiality) broken, second (authentication) held. The code is the **last line** of output, so `verifpal verify model.vp --result-code \| tail -1` gets the code alone; adding `--quiet` silences everything else. With multiple models, each code line is prefixed with the model's path. Verifpal's own test suite pins expected verdicts this way — it is the easiest way to compare two runs. |
| `--sessions N` | Concurrent sessions to analyze per principal, **default 2, range 1–16**. Replicates every principal N times: known values are shared across copies, generated values are freshened. The attacker can carry values between concurrent runs, which is what makes replay attacks reachable. At `--sessions 1` there is no sibling run to replay into. Verdicts are always relative to the session count. |
| `--fail-on-attack` | Exit with status **2** when an attack is found against any query. For CI where a model is expected to verify. Without it, an attack is a *result*, not a run failure. |
| `--auto-queries` | Discard the model's own queries block and analyze a **generated** set of queries (confidentiality/freshness on the values the protocol manipulates). Use to find out what a model gives you, rather than to check what you already believe. |
| `--format text\|json\|html\|tex` | `text` (default) is the human-readable report. `json` is machine-readable; `html` is a self-contained page with a sequence diagram, syntax-highlighted source, and a diagram of the attack; `tex` is a LaTeX table. The three structured formats suppress progress output and color. |
| `-q, --quiet` | Print only what the analysis concluded. With `--result-code`, silences everything but the code. Conflicts with `--verbose`. |
| `-v, --verbose` | Print every step the engine takes (each deduced value, mutation, rule). For understanding why an attack does or doesn't happen. Conflicts with `--quiet`. |
| `--color auto\|always\|never` | ANSI coloring; `auto` (default) honors `NO_COLOR`/`TERM=dumb`. JSON/HTML output is never colored. |

Exit statuses: **0** — normal run (an attack is a result, not a failure); **1** — run failure
(parse/read/validate error); **2** — `--fail-on-attack` and a query was broken.

## Reading attack output

When a query is contradicted, Verifpal prints a `Result` line naming the query and how the attack
was achieved. Two shapes you'll see:

- **Confidentiality:** lists which wire values the attacker controlled and then
  `m1 (m1) is obtained by Attacker`.
  ```
  Result . confidentiality? m1: When the following values are controlled by Attacker:
      ga -> PUBKEY(nil) (originally PUBKEY(a))
      ...
      m1 (m1) is obtained by Attacker.
  ```
- **Authentication:** names the substituted sender and the primitive the tainted value flows into:
  ```
  Result . authentication? Alice -> Bob: secretbox1alice: secretbox1alice, sent by Attacker
      and not by Alice and resolving to AEAD_ENC(...), is used in primitive AEAD_DEC(...) in
      Bob's state.
  ```

A clean run prints something like `Verifpal! verification completed at HH:MM:SS` with no `Result`
lines — meaning **no contradicting scenario was found** (not a proof; see `analysis.md`).

`PUBKEY(nil)` in a trace is the attacker's own crafted public key — the public half of the empty
value `nil`, so the attacker holds the matching private part. It (or `DH_KEX(PUBKEY(nil), …)`)
is the fingerprint of a man-in-the-middle key substitution. In pre-1.0 Verifpal this appeared as
`G^nil`.

## Building from source

Verifpal is written in **Rust**. With Git and the Rust toolchain installed and the repo cloned:

```
cargo build --release      # binary lands in target/release/
```

Install from source is also `cargo build --release` per the README; Homebrew and the Linux
packages otherwise keep the binary auto-updated.

## Editor integrations and the Workbench

- **Editor extensions** (https://verifpal.com/software#editors): Visual Studio Code, Neovim, and
  Zed. They run `verifpal lsp` in the background: live diagnostics, hover documentation for every
  primitive and construct, go-to-definition/references, completion, formatting — and full
  analysis (query verdicts, attack traces) as you edit.
- **Verifpal Workbench** (https://verifpal.com/workbench): run Verifpal in the browser via
  WebAssembly — write, analyze, and share models with no local install.

## Version note

This kit targets **Verifpal 1.6.7**. The language had a major redesign after 0.52 (equations
replaced by `PUBKEY`/`DH_KEX`, `password`/`PW_HASH` removed, `SHAMIR_*` renamed `THRESHOLD_*`,
AEAD taking a nonce, capability brackets, scenarios, sessions) — older binaries reject current
models, and models written against 0.52-era syntax do not parse. Check `verifpal about` when in
doubt.
