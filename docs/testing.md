# What the tests prove, and what they do not

## Running them

```bash
cargo test
```

Unit tests need no server. They cover each rule, including cases where it must stay silent.

```bash
lab/up.sh 17
```

```bash
lab/up.sh 18
```

```bash
lab/up.sh 19
```

```bash
lab/up.sh 20
```

```bash
tests/integration/run.sh target/release/odoo-doctor path/to/linux-binary
```

The labs are deliberately broken Odoo instances bound to localhost. Never expose them. The second binary argument must be a Linux build for your Docker architecture.

## What is verified against real software

| Claim | How it is verified |
|---|---|
| It finds real problems on Odoo 17, 18, 19 and 20 | Each lab is seeded with known problems, and the suite asserts each expected finding |
| It only reads | PostgreSQL logs every statement during an audit, and the suite fails if one of the captured statements writes. It also confirms that PostgreSQL refuses writes in such a session |
| Secrets stay out of reports | The suite searches reports for the seeded passwords and API key |
| Upgrade rules are correct | Rules run on Odoo's own source, and a rule for something removed must not fire on the version that removed it (see below) |
| Docker over SSH behaves like local Docker | Both run against one lab, and the finding counts must match. The remote command runs through a local stand-in for `ssh`, which exercises the real quoting and nesting |
| SSH works | A real OpenSSH server in a container |
| The API client works | Real API keys on each Odoo version, through JSON-RPC and JSON-2 |
| TLS checks work | A real proxy with a self-signed certificate that expires in 5 days, and a valid public site |
| Failures are honest | An unreachable site or SSH host exits 2, not 0 |
| The installer refuses tampered files | Tested by hand with a modified binary. It installed nothing |

## Self-validation on Odoo's own code

With all rules on Odoo's source, upgrade rules behave as their dates predict. This is how the rules were validated, and it found real mistakes in them.

| Rule | Odoo 17 | Odoo 19 | Odoo 20 |
|---|---:|---:|---:|
| `ir.model.access` / `ir.rule` (gone in 20) | 790 | 838 | **0** |
| `get_param` / `set_param` (gone in 20) | 554 | 730 | **0** |
| `odoo.osv.expression` (gone in 20) | 261 | **0** | **0** |
| `<tree>` views (renamed in 18) | 1,344 | **0** | **0** |
| `groups_id` (renamed in 19) | 882 | **0** | **0** |
| `_sql_constraints` (replaced in 19) | 202 | **0** | **0** |
| `attrs` / `states` in views (gone in 17) | **0** | **0** | **0** |

Scanning the source of Odoo 20 took 2.1 s for 1.85 million lines and 142 MB of memory.

### False positives this process caught

Running on real code exposed mistakes unit tests had not:

- `part.get_param('charset')` belongs to Python's email library, not Odoo.
- CSV access files with multi-line domains were parsed wrongly and reported as open to everyone.
- `_inherit = ['a.b', 'mail.thread']` on a model named `a.b` was reported as a new model with no access rule.
- Enterprise modules with no `author` key in their manifest were treated as custom code.
- `-----BEGIN CERTIFICATE-----` was treated as a leaked secret. Only private keys are now.

## What is not verified

- **Real Odoo.sh.** The simulation follows Odoo's documented layout (`~/src/user`, `~/logs/odoo.log`, `psql`, `ODOO_STAGE`), but it is a stand-in. The real environment may differ.
- **Real Odoo Online.** The API path is tested on self-hosted Odoo. Hosted databases may restrict some models.
- **A production-sized database.** The labs are small, with 200,000 rows in the largest custom table. Queries have a 30-second timeout, and a section that fails is reported as not read.
- **Accuracy on your code.** Findings marked "probable" are patterns, and they will have false positives. On Odoo's own code, `sudo()` in public routes and searches in loops fire often, and many of those are deliberate. Rule accuracy has been measured against a limited amount of code outside Odoo itself.
- **Security in general.** Passing these checks does not mean a system is secure.
- **`queue_job` and `fetchmail` checks.** These read tables that the labs do not exercise with failing data.
