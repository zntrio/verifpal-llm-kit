# CLI and tooling

Verifpal is a command-line application, available for Windows, Linux, macOS and FreeBSD. It is
free/open-source software (GPLv3). Get it from https://verifpal.com (Scoop on Windows; Homebrew on
Linux/macOS keep it auto-updated).

## Commands

Run `verifpal` with no arguments to print the version and available options.

| Command | Purpose |
|---|---|
| `verifpal verify model.vp` | Parse, sanity-check, and analyze the model; print query results. The main command. |
| `verifpal pretty model.vp` | Pretty-print / reformat a `.vp` model to make it more readable. |

There is no separate install step — it's a single binary. On Unix, copy it into your `PATH`:

```
cp verifpal /usr/local/bin/verifpal
```

## Building from source

Verifpal is written in **Rust**. With Git and the Rust toolchain installed and the repo cloned:

```
cargo build --release      # binary lands in target/release/
```

Convenience targets: `make build`, `make test`, `make lint`. (There is no advantage over the
pre-built binary.)

## Reading attack output

When a query is contradicted, Verifpal prints a `Result` line naming the query and how the attack
was achieved. Two shapes you'll see:

- **Confidentiality:** lists which wire values the attacker controlled and then
  `m1 (m1) is obtained by Attacker`.
  ```
  Result . confidentiality? m1: When the following values are controlled by Attacker:
      gblongterm -> G^nil (originally G^blongterm)
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

`G^nil` in a trace is the attacker's own crafted Diffie-Hellman public key (private part `nil`) —
the fingerprint of a man-in-the-middle substitution.

## Visual Studio Code extension

Requires Verifpal ≥ 0.40.0. Search "Verifpal" in the Extensions view. Features:

- Syntax highlighting for `.vp` files (immediate).
- Format-on-save / "Format Document" (right-click).
- Hover docs: over a primitive (`HKDF`, `AEAD_ENC`) for its documentation; over a constant for its
  value and creating principal; over a query for its syntax/meaning.
- **Verifpal: Show Protocol Diagram** (Command Palette) — live diagram of the model.
- **Verifpal: Run Attacker Analysis** (Command Palette) — live in-editor analysis. Avoid for
  slow/complex models; prefer the CLI there (you can't edit while analysis runs).

Settings: `verifpal.enabled` (bool), `verifpal.path` (path to the binary).

## Verifpal Workbench

A browser-based environment at https://verifpal.com that runs Verifpal via WebAssembly — write,
analyze, and share models with no local install. Good for sharing a model for discussion.

## Beta status

Verifpal's syntax, semantics, and analysis methodology have been formalized by hand and with the
Coq theorem prover, but it is still classified **beta** given its relative youth compared to tools
like ProVerif (20+ years).
