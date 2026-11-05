//! Language spike: same detection rules as ../python/scan.py, on Ruff's parser.
//! Usage: spike <dir> [--workers N] [--details out.txt]
use rayon::prelude::*;
use ruff_python_ast::visitor::{self, Visitor};
use ruff_python_ast::{self as ast, Expr, InterpolatedStringElement, Operator, Stmt};
use ruff_python_parser::parse_module;
use ruff_text_size::{Ranged, TextSize};
use walkdir::WalkDir;

#[derive(Default)]
struct Res {
    sudo: Vec<usize>,
    sql: Vec<usize>,
    public: Vec<usize>,
    err: usize,
}

struct Scan<'a> {
    src: &'a str,
    starts: Vec<usize>,
    res: Res,
}

impl Scan<'_> {
    fn line(&self, at: TextSize) -> usize {
        let off = at.to_usize();
        match self.starts.binary_search(&off) {
            Ok(i) => i + 1,
            Err(i) => i,
        }
    }
    // The source text is only needed for offsets, kept to mirror the other spikes.
    fn _src(&self) -> &str {
        self.src
    }
}

fn is_cursor(e: &Expr) -> bool {
    let name = match e {
        Expr::Name(n) => n.id.as_str(),
        Expr::Attribute(a) => a.attr.as_str(),
        _ => return false,
    };
    matches!(name, "cr" | "_cr" | "cursor")
}

fn is_dynamic_sql(e: &Expr) -> bool {
    match e {
        Expr::FString(f) => f
            .value
            .elements()
            .any(|el| matches!(el, InterpolatedStringElement::Interpolation(_))),
        Expr::BinOp(b) => matches!(b.op, Operator::Mod | Operator::Add),
        Expr::Call(c) => matches!(&*c.func, Expr::Attribute(a) if a.attr.as_str() == "format"),
        _ => false,
    }
}

fn is_public_route(e: &Expr) -> bool {
    let Expr::Call(c) = e else { return false };
    let Expr::Attribute(a) = &*c.func else { return false };
    if a.attr.as_str() != "route" {
        return false;
    }
    c.arguments.keywords.iter().any(|k| {
        k.arg.as_ref().is_some_and(|n| n.as_str() == "auth")
            && matches!(&k.value, Expr::StringLiteral(s) if s.value.to_str() == "public")
    })
}

impl<'a> Visitor<'a> for Scan<'a> {
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        if let Stmt::FunctionDef(f) = stmt {
            for d in &f.decorator_list {
                if is_public_route(&d.expression) {
                    self.res.public.push(self.line(d.expression.start()));
                }
            }
        }
        visitor::walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &'a Expr) {
        if let Expr::Call(ast::ExprCall { func, arguments, .. }) = expr {
            if let Expr::Attribute(a) = &**func {
                match a.attr.as_str() {
                    "sudo" => self.res.sudo.push(self.line(a.attr.end())),
                    "execute" if is_cursor(&a.value) => {
                        if arguments.args.first().is_some_and(is_dynamic_sql) {
                            self.res.sql.push(self.line(expr.start()));
                        }
                    }
                    _ => {}
                }
            }
        }
        visitor::walk_expr(self, expr);
    }
}

fn scan(path: &std::path::Path) -> Res {
    let Ok(bytes) = std::fs::read(path) else {
        return Res { err: 1, ..Res::default() };
    };
    let src = String::from_utf8_lossy(&bytes);
    let Ok(parsed) = parse_module(&src) else {
        return Res { err: 1, ..Res::default() };
    };
    let mut starts = vec![0];
    starts.extend(src.bytes().enumerate().filter(|(_, b)| *b == b'\n').map(|(i, _)| i + 1));
    let mut s = Scan { src: &src, starts, res: Res::default() };
    s.visit_body(&parsed.syntax().body);
    s.res
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let root = &args[1];
    let opt = |name: &str| args.iter().position(|a| a == name).map(|i| args[i + 1].clone());
    if let Some(w) = opt("--workers") {
        rayon::ThreadPoolBuilder::new()
            .num_threads(w.parse().unwrap())
            .build_global()
            .unwrap();
    }
    let mut files: Vec<_> = WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "py"))
        .map(|e| e.into_path())
        .collect();
    files.sort();
    let results: Vec<Res> = files.par_iter().map(|p| scan(p)).collect();
    let (mut su, mut sq, mut pu, mut er) = (0, 0, 0, 0);
    let mut lines = Vec::new();
    for (path, r) in files.iter().zip(&results) {
        let rel = path.strip_prefix(root).unwrap().display();
        er += r.err;
        su += r.sudo.len();
        sq += r.sql.len();
        pu += r.public.len();
        for (k, v) in [("sudo", &r.sudo), ("sql", &r.sql), ("public", &r.public)] {
            for l in v {
                lines.push(format!("{k} {rel}:{l}"));
            }
        }
    }
    if let Some(d) = opt("--details") {
        lines.sort();
        std::fs::write(d, lines.join("\n") + "\n").unwrap();
    }
    println!(
        "{{\"err\":{er},\"files\":{},\"public\":{pu},\"sql\":{sq},\"sudo\":{su}}}",
        files.len()
    );
}
