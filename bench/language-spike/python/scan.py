#!/usr/bin/env python3
"""Reference implementation for the language spike, built on CPython's ast.

Its findings are the ground truth the Go and Rust parsers are compared against,
because `ast` is the same parser Odoo itself runs on.

Usage: scan.py <dir> [--workers N] [--details out.txt]
"""
import ast
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor


def walk(root):
    for base, _, files in os.walk(root):
        for name in files:
            if name.endswith(".py"):
                yield os.path.join(base, name)


def is_cursor(node):
    if isinstance(node, ast.Name):
        return node.id in ("cr", "_cr", "cursor")
    if isinstance(node, ast.Attribute):
        return node.attr in ("cr", "_cr", "cursor")
    return False


def is_dynamic_sql(node):
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp):
        return isinstance(node.op, (ast.Mod, ast.Add))
    if isinstance(node, ast.Call):
        return isinstance(node.func, ast.Attribute) and node.func.attr == "format"
    return False


def is_public_route(dec):
    if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)):
        return False
    if dec.func.attr != "route":
        return False
    for kw in dec.keywords:
        if kw.arg == "auth" and isinstance(kw.value, ast.Constant):
            return kw.value.value == "public"
    return False


def scan_file(path):
    with open(path, "rb") as fh:
        src = fh.read()
    res = {"sudo": [], "sql": [], "public": [], "err": 0}
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        res["err"] = 1
        return path, res
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "sudo":
                res["sudo"].append(node.func.end_lineno)
            elif (
                node.func.attr == "execute"
                and is_cursor(node.func.value)
                and node.args
                and is_dynamic_sql(node.args[0])
            ):
                res["sql"].append(node.lineno)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                if is_public_route(dec):
                    res["public"].append(dec.lineno)
    return path, res


def main():
    args = sys.argv[1:]
    root = args[0]
    workers = int(args[args.index("--workers") + 1]) if "--workers" in args else 1
    details = args[args.index("--details") + 1] if "--details" in args else None
    files = sorted(walk(root))
    if workers > 1:
        with ProcessPoolExecutor(workers) as pool:
            results = list(pool.map(scan_file, files, chunksize=64))
    else:
        results = [scan_file(p) for p in files]
    totals = {"files": len(files), "sudo": 0, "sql": 0, "public": 0, "err": 0}
    lines = []
    for path, res in results:
        rel = os.path.relpath(path, root)
        totals["err"] += res["err"]
        for kind in ("sudo", "sql", "public"):
            totals[kind] += len(res[kind])
            lines.extend(f"{kind} {rel}:{ln}" for ln in res[kind])
    if details:
        with open(details, "w") as fh:
            fh.write("\n".join(sorted(lines)) + "\n")
    print(json.dumps(totals))


if __name__ == "__main__":
    main()
