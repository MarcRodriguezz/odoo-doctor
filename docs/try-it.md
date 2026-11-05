# Try it yourself

This guide takes about five minutes, plus the time to download Odoo the first time. You will audit a deliberately broken Odoo that runs only on your own machine.

You need [Rust](https://rustup.rs). Steps 2 onward also need Docker, about 4 GB of free disk for the Odoo image, and port 18019 free.

## 1. Build it and check some code

No Odoo or Docker is needed for this step.

```bash
cargo build --release
```

```bash
target/release/odoo-doctor --addons lab/addons --target-version 20
```

You should see findings such as `SQL built with string formatting` and `eval() or exec() on dynamic input`, each pointing at a line in `lab/addons/lab_broken`. Open that file and compare. Most functions in `models/order.py` contain one deliberate mistake.

You also get a score marked **limited check**, because only one area could be examined.

## 2. Start the broken Odoo

```bash
lab/up.sh 19
```

It installs Odoo 19 and adds problems to it, such as extra administrators, failed emails and a bad configuration. It finishes with `lab 19 ready on http://127.0.0.1:18019`. To use another version, change the number: 17, 18 or 20.

## 3. Run a full audit

```bash
target/release/odoo-doctor --docker oddoc-lab-19-odoo-1
```

Expect a very low score, about 19 out of 100, with grade F. The section **What was checked** should show nearly every area with a tick. External exposure shows `~`, because a local address cannot be exposed.

Then open the report it wrote, `odoo-doctor-report.html`. On macOS:

```bash
open odoo-doctor-report.html
```

Try the filters above the findings, and expand one to read why it matters and how to fix it.

## 4. See the other ways to run it

Only from outside, as a stranger would see it:

```bash
target/release/odoo-doctor http://127.0.0.1:18019
```

There are few findings here, and no grade. That is correct: a local address hides exposure problems, and nothing else is reachable.

The same view, treated as if the address were public:

```bash
target/release/odoo-doctor http://127.0.0.1:18019 --treat-as-public --no-port-probe
```

Now it finds `Database manager is reachable` and `Site is served without HTTPS`.

A report that is safe to share, with logins and database names masked:

```bash
target/release/odoo-doctor --docker oddoc-lab-19-odoo-1 --redact --html shared.html
```

The check catalog:

```bash
target/release/odoo-doctor checks
```

```bash
target/release/odoo-doctor explain PY001
```

## 5. Try your own code

This only reads the folder, and nothing leaves your machine.

```bash
target/release/odoo-doctor --addons /path/to/your/addons --target-version 20
```

If a finding looks wrong, that is useful: please [report it](../CONTRIBUTING.md). Findings marked **probable** are patterns, so some will be false alarms.

## 6. Clean up

This deletes the lab's containers and data.

```bash
docker compose -p oddoc-lab-19 -f lab/compose.yml down -v
```

To also free the disk space of the Odoo image:

```bash
docker image rm odoo:19
```

## Trouble

- **`several Odoo containers are running`:** name one with `--docker NAME`.
- **`no Odoo found on this machine`:** Docker may not be running, or Odoo may be somewhere the tool does not look. Use `--conf /path/to/odoo.conf`, or `--docker NAME`.
- **`lab/up.sh` says a port is in use:** pick another one, for example `lab/up.sh 19 18119`.

To run the project's automated tests, see [testing.md](testing.md).
