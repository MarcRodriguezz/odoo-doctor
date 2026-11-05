# odoo-doctor

**A read-only health, security and upgrade audit for any Odoo deployment. It is one small binary with nothing else to install.**

Run it on the server and it finds Odoo by itself: its configuration, database, custom modules and logs. A few seconds later you know what is wrong, why it matters, and how to fix it.

```text
$ odoo-doctor

Found Odoo in container odoo-app
Reading the database with psql on container odoo-db
Analyzing custom modules in /mnt/extra-addons

odoo-doctor 0.1.0
Odoo 19.0-20260528 · database production

19/100  grade F
2 critical · 13 high · 15 medium · 3 low · 2 info

  Security      ███░░░░░░░  28
  Reliability   ████████░░  83
  Performance   █████████░  86
  Upgrade       ██████████  97
  Code quality  ██████████  99

 CRITICAL  Master password is weak or a default CFG001
  `admin_passwd` is a common value or too short. The value is not shown here.
  Fix: Set a long random `admin_passwd`. Odoo stores a hash of it after you change it in the manager.

 HIGH  SQL built with string formatting PY001 (probable)
  2 occurrence(s) in 1 module(s).
  → /mnt/extra-addons/acme_sale/models/order.py:22
  Fix: Pass values as parameters: `cr.execute("... WHERE id = %s", (id,))`, or use `odoo.tools.SQL`.

Report: odoo-doctor-report.html
```

The output above comes from a deliberately broken test instance. [See its full HTML report](docs/sample-report.html).

## Install

**Linux and macOS**

```bash
curl -fsSL https://raw.githubusercontent.com/MarcRodriguezz/odoo-doctor/main/install.sh | sh
```

**Windows (PowerShell)**

```powershell
irm https://raw.githubusercontent.com/MarcRodriguezz/odoo-doctor/main/install.ps1 | iex
```

Neither needs root or administrator rights. Both verify the download's SHA-256 checksum. You can also [download a binary](https://github.com/MarcRodriguezz/odoo-doctor/releases) yourself. There are builds for x86-64 and ARM64.

**Want to try it first?** [This guide](docs/try-it.md) walks you through auditing a deliberately broken Odoo on your own machine.

## Use

| Your setup | Command |
|---|---|
| On the Odoo server (native or Docker) | `odoo-doctor` |
| A specific container | `odoo-doctor --docker my-odoo` |
| A remote server (native or Docker) | `odoo-doctor --ssh user@server` |
| An Odoo.sh branch | `odoo-doctor --ssh 12345@my-project.odoo.com` |
| Odoo Online, or any site through its API | `odoo-doctor https://x.odoo.com --login me@x.com --api-key KEY` |
| Any site from outside, with no credentials | `odoo-doctor https://erp.example.com` |
| Just the code, for an upgrade or CI | `odoo-doctor --addons ./addons --target-version 20` |

Your keys and config for `ssh` and `docker` work as usual, because odoo-doctor runs those commands. Run `odoo-doctor --help` for every option.

## What it checks

It has [111 checks](src/checks/catalog.rs), each with an explanation and a fix. List them with `odoo-doctor checks`, or read about one with `odoo-doctor explain PY001`.

| Layer | Examples |
|---|---|
| **External exposure** | Database manager reachable, public database list, no HTTPS, bad or expiring certificate, ports 8069 and 5432 open, unsupported version |
| **Odoo configuration** | Weak master password, `workers = 0`, `dev_mode` on, debug logs, missing limits, readable `odoo.conf`, superuser database role |
| **Users and access** | Too many or inactive administrators, no 2FA, portal users with admin rights, unhashed passwords, access rules open to everyone |
| **Operations** | Failing or overdue crons, stuck email queue, modules stuck mid-install, failed background jobs, attachments in the database |
| **PostgreSQL** | End-of-life version, default memory settings, long transactions, locks, autovacuum, sequential scans, missing and unused indexes, slowest queries |
| **Custom module code** | SQL injection, `sudo()` in public routes, `eval`, unsafe pickle, disabled TLS checks, hardcoded secrets, `cr.commit()`, N+1 searches |
| **Upgrade readiness** | Code that breaks on the next Odoo version, including Odoo 20's move to `ir.access` |
| **Logs and host** | Recurring errors, workers killed by limits, deadlocks, disk nearly full |

### Upgrade checks come from Odoo's source

Each "removed in version X" rule was checked by scanning the actual source code of Odoo 17, 19 and 20. For example, Odoo 20 removes `ir.model.access`, `ir.rule`, `get_param`/`set_param` and `odoo.osv`, and a module that uses them will not load.

## Safe by design

- **It only reads.** Every database session runs with `default_transaction_read_only = on`, so PostgreSQL itself refuses writes. The API client can only send `search_read`, `search_count` and `fields_get`. The integration suite captures the SQL statements from an audit in PostgreSQL's log and fails if any of them writes.
- **It keeps secrets out.** Queries never select secret columns. Where a secret matters, PostgreSQL computes a yes-or-no answer about it. The master password is classified and then dropped.
- **Nothing leaves your machine.** There is no telemetry, no account and no upload. It only connects to the system you point it at.
- **It never guesses.** It never tries to log in or to guess a password.
- **It is gentle on production.** It uses half the available cores, sets statement and lock timeouts on its database sessions, and needs about 140 MB to analyze 1.8 million lines of code.

The HTML report can include logins and database names. Use `--redact` before sharing it outside your team.

**Only audit systems you own or have permission to test.**

## Reading the result

The score starts at 100 and falls with each finding, weighted by severity. A critical finding caps the grade at D. Findings marked **probable** come from a code pattern, so a person should confirm them.

Every report lists **what was checked and what was not**, with the reason. If fewer than four areas could be examined, for example with only an address and no credentials, you get a score but no grade. Even a good grade covers only what was examined, and it does not prove the system is secure.

Code in modules that are not installed is downgraded, since it cannot cause harm until someone installs it. On hosted Odoo, settings only the operator controls are hidden.

## Use it in CI

```yaml
- run: curl -fsSL https://raw.githubusercontent.com/MarcRodriguezz/odoo-doctor/main/install.sh | sh
- run: ~/.local/bin/odoo-doctor --addons . --target-version 20 --fail-on high --sarif results.sarif --no-html
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

Exit codes: `0` completed, `1` a finding reached `--fail-on`, `2` nothing could be examined or the arguments are wrong.

## Compatibility

| Environment | Status |
|---|---|
| Odoo 17, 18, 19, 20 with Docker | Tested end to end against real instances |
| Package install, no Docker | Tested end to end, inside the official Odoo image |
| Remote server over SSH | Tested through SSH, both native and Docker |
| Odoo API (JSON-RPC on 17 and 18, JSON-2 on 19 and 20) | Tested against real instances with real API keys |
| **Odoo.sh** | Tested against a simulated build with the documented layout. **Not yet tested on a real Odoo.sh project** |
| **Odoo Online** | Uses the tested API path. **Not yet tested on a real Odoo Online database.** Odoo limits API access to its Custom plan |
| Linux and macOS, x86-64 and ARM64 | Tests pass in CI on real machines. The full suite against real Odoo runs on Linux x86-64 |
| **Windows** | Unit tests and code-only runs pass on real Windows machines (x86-64 and ARM64). **A real Odoo on Windows is not yet tested.** Its native install is read directly, and the disk check is not available yet |

See [docs/testing.md](docs/testing.md) for what the tests prove and what they do not.

## How it is built

Written in Rust, using [Ruff](https://github.com/astral-sh/ruff)'s Python parser. Collectors gather facts into one struct, and each check is a pure function over it, so most rules have unit tests that need no server.

[ADR 0001](docs/adr/0001-language.md) explains the language choice with measurements: Rust, Go and Python each analyzed 1.1 million lines of real Odoo code. Parsing took 0.34 s in Rust, 3.45 s in Python and 8.62 s in pure Go, with identical results.

## Contributing

Contributions are welcome, and new checks and false-positive reports especially. See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). odoo-doctor is an independent project, not affiliated with or endorsed by Odoo S.A.
