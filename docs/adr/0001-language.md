# ADR 0001: Implementation language

**Status:** accepted. **Date:** 2026-11-05.

## Decision

odoo-doctor is written in **Rust**, using Ruff's Python parser, `rustls` for TLS,
and one static binary per platform.

The initial proposal was Go. The measurements below changed that decision.

## What was tested

The rules and the corpus were the same for every language. The corpus is every `.py`
file under `odoo/addons` in the `odoo:19` image: **8,387 files, 1.1M lines, 50 MB**.
Each implementation counts `.sudo()` calls, cursor `execute()` calls with dynamic SQL,
and `auth='public'` routes. CPython's `ast` is the ground truth, because it is the
parser Odoo itself runs on.

Machine: Apple Silicon, 10 cores, macOS. Sources are in `bench/language-spike/`.

### Parsing the corpus

Wall time is the mean of 5 `hyperfine` runs. Memory is peak RSS from a separate
`/usr/bin/time -l` run with 10 workers.

| Implementation | Time (10 workers) | Peak memory | Matches ground truth | Spike binary |
|---|---:|---:|---|---:|
| **Rust + `ruff_python_parser`** | **0.34 s** | **19 MB** | 5,253 / 5,253 | **1.6 MB** |
| Python 3.12 `ast` | 3.45 s | 59 MB per process | reference | needs Python |
| Go + tree-sitter (cgo) | 3.54 s | 55 MB | 5,253 / 5,253 | 3.0 MB |
| Go + `gotreesitter` (pure Go) | 8.62 s | 569 MB | 5,253 / 5,253 | 9.5 MB |

Python's result depends on the interpreter it runs under. On the macOS system
Python 3.9, 29 files failed to parse and 163 `sudo()` calls were missed.

On a realistic custom codebase (42 files, 3,000 lines), every option finished in under
0.2 s. **Speed alone would not decide this.** Memory matters more, because this tool
may run on a production Odoo server: on that same small codebase, pure Go used 80 MB and
Rust used 4 MB.

### Full stack

Each prototype links an HTTPS client, a Postgres driver, HTML templates, a CLI parser
and the Python parser.

| | Rust | Go (pure) | Python + PyInstaller |
|---|---:|---:|---:|
| Binary size | 4.0–4.7 MB | 20–22 MB | 15 MB |
| Time to `--help` | 4.3 ms | 9.0 ms | 3.6 s (onefile, macOS) |
| Third-party packages | 173 crates | 23 modules | 5 direct |
| Clean release build | 60 s | 7 s | 15 s |
| Cross-compile build per target | 80–100 s | about 16 s | not supported |
| Toolchain to cross-compile | rustup + zig + cargo-zigbuild | none | one build machine per OS |

Both native prototypes cross-compiled for Linux, macOS and Windows on x86-64 and ARM64.
The Linux builds (both architectures) and the macOS arm64 build also ran for real, doing
HTTPS and Postgres, in empty Alpine containers or natively. The Windows builds were
compiled but not executed at this stage; CI runs them on real Windows runners.

## Why Rust

1. **Same accuracy, far lighter.** Rust matched `ast` exactly, 10 times faster than the
   next option and with the lowest memory. A diagnostic tool should not disturb the
   production server it is examining.
2. **A real Python AST.** Ruff's parser gives a typed tree shaped much like Python's
   `ast`, and it does not depend on the interpreter installed on the target machine.
3. **Smallest download**, which supports the main goal: easy installation everywhere.

## What we accept in exchange

- **Ruff's parser is an internal crate** (`0.0.x`, "internal component of Ruff"), so its
  API can change without notice. Mitigation: the version is pinned exactly and all use
  of it stays inside `src/code/`, so it can be replaced without touching the rules.
- **173 crates is a large supply chain.** Mitigation: `cargo-deny` in CI and a committed
  `Cargo.lock`. This already paid off: it caught two known vulnerabilities in `quick-xml`
  0.38 before the first release.
- **Slower builds and a steeper language**, which is the cost of Rust for contributors.
  Mitigation: a rule is a small pure function over collected data, so adding one does not
  require touching async, lifetimes or transport code.
- **Contributions from the Odoo community would have been easier in Python.** This is
  the strongest argument against the decision, and it remains true.

## Why not the others

- **Go** would have been the choice if parsing did not matter. It has the simplest
  cross-compilation and the smallest dependency tree. But the pure Go parser costs 30
  times more memory, and the cgo parser gives up the easy cross-compilation that was
  Go's main advantage.
- **Python** has the best parser fit and the best community fit. But it either requires
  a suitable interpreter on the machine, or a PyInstaller bundle with a 3.6 s start on
  macOS and one build machine per OS. Docker hosts and consultants' Windows laptops
  often have no suitable Python.

## How to revisit this

Reconsider if Ruff's parser stops being published, or if community contributions become
a higher priority than footprint and installation. The rules are isolated from transport
and parsing, which limits what a port would cost.
