# Language spike

The measurements behind [ADR 0001](../../docs/adr/0001-language.md). Each folder implements the same detection rules on a different parser. `python/scan.py` is the reference, because Odoo itself runs on CPython's `ast`.

| Folder | Implementation |
|---|---|
| `python/` | CPython `ast` |
| `rust/` | `ruff_python_parser` |
| `go/` | `gotreesitter`, pure Go |
| `go-cgo/` | tree-sitter through cgo |
| `full-rust/`, `full-go/` | Prototypes linking HTTPS, Postgres, templates, CLI and parser, to compare binary size and cross-compilation |

## Reproducing it

Extract the corpus, which is every Python file of Odoo's addons in the `odoo:19` image. It is not committed.

```bash
mkdir -p corpus && docker run --rm --entrypoint sh odoo:19 -c 'cd /usr/lib/python3/dist-packages/odoo && find addons -name "*.py" -print0 | tar --null -T - -cf -' | tar -xf - -C corpus
```

Build each implementation, and run them with the same arguments.

```bash
(cd rust && cargo build --release) && rust/target/release/spike corpus --workers 10 --details rust.txt
```

```bash
(cd go && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -tags 'grammar_subset grammar_subset_python' -o bin/spike .) && go/bin/spike corpus --workers 10 --details go.txt
```

```bash
python3 python/scan.py corpus --workers 10 --details python.txt
```

Then compare the sorted detail files. All of them matched exactly on Python 3.12. On Python 3.9, `ast` failed on 29 files, which is one reason not to depend on the interpreter a server happens to have.
