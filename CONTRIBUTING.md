# Contributing

## Reporting a false positive

False positives are bugs, and they are the most useful reports you can send. Please include the check ID and the smallest piece of code or configuration that triggers it. Remove anything private first, and use `--redact` on reports.

## Adding a check

1. Add the rule to `src/checks/catalog.rs`, with why it matters and how to fix it.
2. Emit it from `src/checks/mod.rs` if it reads server data, or from `src/code/python.rs` or `src/code/xml.rs` if it reads code.
3. Add a unit test where it fires and, just as important, one where it must stay silent.

Checks are pure functions over collected data, so most of them need no server to test.

A check about removed or deprecated Odoo APIs also needs evidence from Odoo's source code, and an entry in `UPGRADE_RULES`. Run it on Odoo's own code: it should stop firing on the version that removed the API.

## Principles

- **Read only.** Never add anything that writes to the audited system. API methods are allowlisted in `src/collect/api.rs`, and SQL sessions are read-only.
- **No secrets in output.** Do not select secret columns. Compute a boolean in SQL instead, as the password check does.
- **Be honest about coverage.** If something could not be read, record it, so the report does not imply it was clean.
- **Keep the confidence honest.** Use `Probable` for anything inferred from a pattern.

## Before opening a pull request

```bash
cargo fmt
```

```bash
cargo clippy --all-targets -- -D warnings
```

```bash
cargo test
```

See [docs/testing.md](docs/testing.md) for the integration tests against real Odoo. CI runs them on every pull request.
