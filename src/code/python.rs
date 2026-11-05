//! Python analysis on Ruff's AST. This module and `manifest` are the only ones that know the
//! parser's API, so swapping parsers would not touch the rules. See docs/adr/0001-language.md.
use super::Hit;
use ruff_python_ast::visitor::{self, Visitor};
use ruff_python_ast::{
    self as ast, ExceptHandler, Expr, InterpolatedStringElement, Operator, Stmt,
};
use ruff_python_parser::parse_module;
use ruff_text_size::{Ranged, TextSize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Default)]
pub struct PyResult {
    pub hits: Vec<Hit>,
    /// `_name` values of models defined in this file.
    pub models: Vec<(String, usize)>,
    pub parse_error: Option<(usize, String)>,
    pub lines: usize,
}

struct Scan<'a> {
    src: &'a str,
    starts: Vec<usize>,
    res: PyResult,
    in_tests: bool,
    in_migration: bool,
    loop_depth: u32,
    public_route: bool,
    class_depth: u32,
    dynamic_sql_vars: HashSet<String>,
    managed_cursors: HashSet<String>,
}

const HTTP_VERBS: &[&str] = &["get", "post", "put", "patch", "delete", "head", "request"];
const SUBPROCESS_FNS: &[&str] = &["run", "call", "Popen", "check_output", "check_call"];

fn is_cursor_expr(e: &Expr) -> bool {
    let name = match e {
        Expr::Name(n) => n.id.as_str(),
        Expr::Attribute(a) => a.attr.as_str(),
        _ => return false,
    };
    matches!(name, "cr" | "_cr" | "cursor" | "new_cr")
}

fn attr_on_name(e: &Expr) -> Option<(&str, &str)> {
    if let Expr::Attribute(a) = e {
        if let Expr::Name(n) = &*a.value {
            return Some((n.id.as_str(), a.attr.as_str()));
        }
    }
    None
}

fn kwarg<'e>(args: &'e ast::Arguments, name: &str) -> Option<&'e Expr> {
    args.keywords
        .iter()
        .find(|k| k.arg.as_ref().is_some_and(|a| a.as_str() == name))
        .map(|k| &k.value)
}

fn is_true(e: Option<&Expr>) -> bool {
    matches!(e, Some(Expr::BooleanLiteral(b)) if b.value)
}

fn is_false(e: Option<&Expr>) -> bool {
    matches!(e, Some(Expr::BooleanLiteral(b)) if !b.value)
}

fn str_value(e: &Expr) -> Option<String> {
    match e {
        Expr::StringLiteral(s) => Some(s.value.to_str().to_string()),
        _ => None,
    }
}

fn looks_like_placeholder(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    [
        "change", "example", "test", "xxx", "your", "dummy", "demo", "none", "todo", "<", "{",
        "%s", "password", "secret", "sample", "fake", "http",
    ]
    .iter()
    .any(|p| v.contains(p))
}

fn has_secret_prefix(value: &str) -> bool {
    [
        "sk_live_",
        "rk_live_",
        "ghp_",
        "github_pat_",
        "xoxb-",
        "AKIA",
        "AIza",
    ]
    .iter()
    .any(|p| value.starts_with(p))
        || (value.trim_start().starts_with("-----BEGIN") && value.contains("PRIVATE KEY"))
}

fn is_secret_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "auth_token",
        "access_token",
        "private_key",
    ]
    .iter()
    .any(|w| n.contains(w))
}

impl Scan<'_> {
    fn line(&self, at: TextSize) -> usize {
        let off = at.to_usize();
        match self.starts.binary_search(&off) {
            Ok(i) => i + 1,
            Err(i) => i,
        }
    }

    fn hit(&mut self, rule: &'static str, at: TextSize, detail: impl Into<String>) {
        if self.in_tests && !rule.starts_with("UPG") {
            return;
        }
        // Old migration scripts never run again, so they cannot break an upgrade.
        if self.in_migration && rule.starts_with("UPG") {
            return;
        }
        let line = self.line(at);
        self.res.hits.push(Hit {
            rule,
            file: String::new(),
            line,
            detail: detail.into(),
        });
    }

    fn text(&self, e: &impl Ranged) -> &str {
        &self.src[e.range()]
    }

    /// Interpolating `self._table` is the normal way to name a table and is not injection.
    fn only_table_names(&self, text: &str) -> bool {
        let is_constant = !text.is_empty()
            && text
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
        // Report models build SQL from their own helpers, such as `self._select()`.
        is_constant
            || (text.contains("_table") && !text.contains(','))
            || (text.starts_with("self._") && !text.contains(','))
    }

    fn is_dynamic_sql(&self, e: &Expr) -> bool {
        match e {
            Expr::FString(f) => {
                let mut any = false;
                for el in f.value.elements() {
                    if let InterpolatedStringElement::Interpolation(i) = el {
                        if !self.only_table_names(self.text(&*i.expression)) {
                            any = true;
                        }
                    }
                }
                any
            }
            Expr::BinOp(b) => match b.op {
                Operator::Mod => !self.only_table_names(self.text(&*b.right)),
                Operator::Add => {
                    !(matches!(&*b.left, Expr::StringLiteral(_))
                        && matches!(&*b.right, Expr::StringLiteral(_)))
                }
                _ => false,
            },
            Expr::Call(c) => {
                matches!(&*c.func, Expr::Attribute(a) if a.attr.as_str() == "format")
                    && !c
                        .arguments
                        .args
                        .iter()
                        .all(|x| self.only_table_names(self.text(x)))
            }
            _ => false,
        }
    }

    fn is_config_parameter(&self, receiver: &Expr) -> bool {
        let text = self.text(receiver).to_ascii_lowercase();
        text.contains("config_parameter")
            || text.contains("configparam")
            || text.contains("icp")
            || text.ends_with("params")
    }

    fn check_call(&mut self, call: &ast::ExprCall, whole: &Expr) {
        let start = whole.start();
        if let Expr::Name(n) = &*call.func {
            if matches!(n.id.as_str(), "eval" | "exec") {
                let literal = matches!(call.arguments.args.first(), Some(Expr::StringLiteral(_)));
                if !literal {
                    let name = n.id.to_string();
                    self.hit("PY004", start, format!("{name}() on a non-literal value"));
                }
            }
            return;
        }
        let Expr::Attribute(attr) = &*call.func else {
            return;
        };
        let method = attr.attr.as_str();
        match method {
            "execute" if is_cursor_expr(&attr.value) && !self.in_migration => {
                if let Some(first) = call.arguments.args.first() {
                    let via_var = matches!(first, Expr::Name(n) if self.dynamic_sql_vars.contains(n.id.as_str()));
                    if self.is_dynamic_sql(first) || via_var {
                        let snippet: String = self.text(first).chars().take(70).collect();
                        self.hit("PY001", start, snippet);
                    }
                }
            }
            "commit" if is_cursor_expr(&attr.value) && !self.in_migration => {
                let receiver = self.text(&*attr.value).to_string();
                if !self.managed_cursors.contains(&receiver) {
                    self.hit("PY010", start, format!("{receiver}.commit()"));
                }
            }
            "sudo" if self.public_route => {
                self.hit("PY002", attr.attr.end(), "sudo() inside a public route");
            }
            "search" | "search_count" | "search_read" | "search_fetch"
                if self.loop_depth > 0
                    && !self.in_migration
                    && self.text(&*attr.value).contains("env") =>
            {
                self.hit("PY012", start, format!(".{method}() inside a loop"));
            }
            // `get_param` also exists on other objects, such as `email.message.Message`.
            "get_param" | "set_param" if self.is_config_parameter(&attr.value) => {
                self.hit("UPG002", start, format!(".{method}()"));
            }
            "read_group" => self.hit("UPG018", start, ".read_group()"),
            _ => {}
        }
        if let Some((module, func)) = attr_on_name(&call.func) {
            let dynamic = !matches!(call.arguments.args.first(), Some(Expr::StringLiteral(_)));
            match (module, func) {
                ("pickle" | "cPickle" | "dill" | "marshal", "loads" | "load") => {
                    self.hit("PY005", start, format!("{module}.{func}()"))
                }
                ("yaml", "load") => {
                    if !self.text(&call.arguments).contains("SafeLoader") {
                        self.hit("PY005", start, "yaml.load() without SafeLoader");
                    }
                }
                ("os", "system" | "popen") if dynamic => self.hit(
                    "PY006",
                    start,
                    format!("os.{func}() with a dynamic command"),
                ),
                ("subprocess", f)
                    if SUBPROCESS_FNS.contains(&f)
                        && is_true(kwarg(&call.arguments, "shell"))
                        && dynamic =>
                {
                    self.hit("PY006", start, format!("subprocess.{f}(shell=True)"));
                }
                ("requests", f) if HTTP_VERBS.contains(&f) => {
                    if is_false(kwarg(&call.arguments, "verify")) {
                        self.hit("PY007", start, format!("requests.{f}(verify=False)"));
                    }
                    if kwarg(&call.arguments, "timeout").is_none() {
                        self.hit("PY011", start, format!("requests.{f}() without timeout"));
                    }
                }
                ("fields", "Html") if is_false(kwarg(&call.arguments, "sanitize")) => {
                    self.hit("PY009", start, "fields.Html(sanitize=False)");
                }
                _ => {}
            }
        }
        if kwarg(&call.arguments, "group_operator").is_some() {
            self.hit("UPG006", start, "group_operator=");
        }
    }

    fn handle_route(&mut self, function: &ast::StmtFunctionDef) -> bool {
        let mut is_public = false;
        for dec in &function.decorator_list {
            let Expr::Call(call) = &dec.expression else {
                continue;
            };
            let Expr::Attribute(attr) = &*call.func else {
                continue;
            };
            if attr.attr.as_str() != "route" {
                continue;
            }
            let auth = kwarg(&call.arguments, "auth")
                .and_then(str_value)
                .unwrap_or_else(|| "user".into());
            let route_type = kwarg(&call.arguments, "type")
                .and_then(str_value)
                .unwrap_or_else(|| "http".into());
            let public = matches!(auth.as_str(), "public" | "none");
            if route_type == "json" {
                self.hit("UPG020", dec.expression.start(), "route type='json'");
            }
            is_public |= public;
            let reads_only = kwarg(&call.arguments, "methods").is_some_and(|m| {
                let text = self.text(m).to_ascii_uppercase();
                !["POST", "PUT", "PATCH", "DELETE"]
                    .iter()
                    .any(|v| text.contains(v))
            });
            if public
                && route_type == "http"
                && is_false(kwarg(&call.arguments, "csrf"))
                && !reads_only
            {
                let name = function.name.to_string();
                self.hit(
                    "PY003",
                    dec.expression.start(),
                    format!("{name}(): auth='{auth}', csrf=False"),
                );
            }
        }
        is_public
    }

    fn check_secret_assignment(&mut self, target: &Expr, value: &Expr, at: TextSize) {
        let Some(text) = str_value(value) else { return };
        let name = match target {
            Expr::Name(n) => n.id.to_string(),
            Expr::Attribute(a) => a.attr.to_string(),
            _ => return,
        };
        if has_secret_prefix(&text) {
            self.hit(
                "PY008",
                at,
                format!("{name} = <recognized credential format>"),
            );
        } else if is_secret_name(&name)
            && text.len() >= 10
            && !looks_like_placeholder(&text)
            && !text.contains(' ')
        {
            self.hit("PY008", at, format!("{name} = <{} characters>", text.len()));
        }
    }

    fn check_import(&mut self, module: &str, at: TextSize, names: &[String]) {
        if module == "openerp" || module.starts_with("openerp.") {
            self.hit("UPG014", at, format!("import {module}"));
        }
        if module == "odoo.osv.expression"
            || module == "odoo.osv"
            || (module == "odoo" && names.iter().any(|n| n == "osv"))
        {
            self.hit("UPG003", at, format!("import from {module}"));
        }
        if module == "xmlrpc.client" || module == "xmlrpclib" {
            self.hit("UPG016", at, format!("import {module}"));
        }
    }
}

impl<'a> Visitor<'a> for Scan<'a> {
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        match stmt {
            Stmt::FunctionDef(function) => {
                let name = function.name.as_str();
                if self.class_depth > 0 && name == "name_get" {
                    self.hit("UPG008", function.name.start(), "def name_get()");
                }
                if self.class_depth > 0 && name == "fields_view_get" {
                    self.hit("UPG014", function.name.start(), "def fields_view_get()");
                }
                if self.class_depth > 0 && name == "read_group" {
                    self.hit("UPG018", function.name.start(), "def read_group()");
                }
                let public = self.handle_route(function);
                let saved_public = self.public_route;
                let saved_loop = self.loop_depth;
                let saved_vars = std::mem::take(&mut self.dynamic_sql_vars);
                let saved_cursors = std::mem::take(&mut self.managed_cursors);
                self.public_route = self.public_route || public;
                self.loop_depth = 0;
                visitor::walk_stmt(self, stmt);
                self.public_route = saved_public;
                self.loop_depth = saved_loop;
                self.dynamic_sql_vars = saved_vars;
                self.managed_cursors = saved_cursors;
                return;
            }
            Stmt::ClassDef(class) => {
                let bases = class
                    .arguments
                    .as_ref()
                    .map(|a| self.text(&**a).to_string())
                    .unwrap_or_default();
                let is_model =
                    bases.contains("models.Model") || bases.contains("models.TransientModel");
                if is_model {
                    let mut model_name = None;
                    let mut inherit = String::new();
                    for inner in &class.body {
                        if let Stmt::Assign(assign) = inner {
                            if let Some(Expr::Name(n)) = assign.targets.first() {
                                match n.id.as_str() {
                                    "_name" => model_name = str_value(&assign.value),
                                    // A string or a list: `_inherit = ['a.b', 'mail.thread']`.
                                    "_inherit" => inherit = self.text(&*assign.value).to_string(),
                                    "_sql_constraints" => {
                                        self.hit("UPG009", inner.start(), "_sql_constraints");
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    if let Some(model) = model_name.filter(|_| !self.in_tests) {
                        let extends_itself = inherit.contains(&format!("'{model}'"))
                            || inherit.contains(&format!("\"{model}\""));
                        if !extends_itself {
                            let line = self.line(class.name.start());
                            self.res.models.push((model, line));
                        }
                    }
                }
                self.class_depth += 1;
                visitor::walk_stmt(self, stmt);
                self.class_depth -= 1;
                return;
            }
            Stmt::For(_) | Stmt::While(_) => {
                self.loop_depth += 1;
                visitor::walk_stmt(self, stmt);
                self.loop_depth -= 1;
                return;
            }
            Stmt::With(with) => {
                let mut added = Vec::new();
                for item in &with.items {
                    let context = self.text(&item.context_expr);
                    if context.contains("cursor(") {
                        if let Some(var) = &item.optional_vars {
                            let name = self.text(&**var).to_string();
                            if self.managed_cursors.insert(name.clone()) {
                                added.push(name);
                            }
                        }
                    }
                }
                visitor::walk_stmt(self, stmt);
                for name in added {
                    self.managed_cursors.remove(&name);
                }
                return;
            }
            Stmt::Assign(assign) => {
                if let Some(target) = assign.targets.first() {
                    self.check_secret_assignment(target, &assign.value, stmt.start());
                    if let Expr::Name(n) = target {
                        if self.is_dynamic_sql(&assign.value) {
                            self.dynamic_sql_vars.insert(n.id.to_string());
                        } else {
                            self.dynamic_sql_vars.remove(n.id.as_str());
                        }
                        // `cr = registry.cursor()` is managed by the code that opened it.
                        if self.text(&*assign.value).contains("cursor()") {
                            self.managed_cursors.insert(n.id.to_string());
                        }
                    }
                }
            }
            Stmt::Import(import) => {
                for alias in &import.names {
                    self.check_import(alias.name.as_str(), stmt.start(), &[]);
                }
            }
            Stmt::ImportFrom(import) => {
                if let Some(module) = &import.module {
                    let names: Vec<String> =
                        import.names.iter().map(|a| a.name.to_string()).collect();
                    self.check_import(module.as_str(), stmt.start(), &names);
                }
            }
            _ => {}
        }
        visitor::walk_stmt(self, stmt);
    }

    fn visit_except_handler(&mut self, handler: &'a ExceptHandler) {
        let ExceptHandler::ExceptHandler(h) = handler;
        let broad = match h.type_.as_deref() {
            None => true,
            Some(Expr::Name(n)) => matches!(n.id.as_str(), "Exception" | "BaseException"),
            _ => false,
        };
        if broad && h.body.len() == 1 && matches!(h.body[0], Stmt::Pass(_)) {
            self.hit("PY013", handler.start(), "except: pass");
        }
        visitor::walk_except_handler(self, handler);
    }

    fn visit_expr(&mut self, expr: &'a Expr) {
        match expr {
            Expr::Call(call) => self.check_call(call, expr),
            Expr::Attribute(attr) => {
                let name = attr.attr.as_str();
                if let Expr::Name(base) = &*attr.value {
                    if base.id.as_str() == "self" && matches!(name, "_cr" | "_uid" | "_context") {
                        self.hit("UPG010", expr.start(), format!("self.{name}"));
                    }
                    if base.id.as_str() == "api" && matches!(name, "multi" | "one" | "returns") {
                        self.hit("UPG014", expr.start(), format!("api.{name}"));
                    }
                }
                if name == "groups_id" {
                    self.hit("UPG011", expr.start(), ".groups_id");
                }
            }
            Expr::StringLiteral(s) => {
                let value = s.value.to_str();
                if value == "groups_id" {
                    self.hit("UPG011", expr.start(), "'groups_id'");
                } else if value == "/jsonrpc" || value.starts_with("/xmlrpc") {
                    let text = value.to_string();
                    self.hit("UPG016", expr.start(), text);
                } else if has_secret_prefix(value) {
                    self.hit("PY008", expr.start(), "<recognized credential format>");
                }
            }
            Expr::ListComp(_) | Expr::SetComp(_) | Expr::DictComp(_) | Expr::Generator(_) => {
                self.loop_depth += 1;
                visitor::walk_expr(self, expr);
                self.loop_depth -= 1;
                return;
            }
            _ => {}
        }
        visitor::walk_expr(self, expr);
    }
}

pub fn scan(path: &str, src: &str) -> PyResult {
    let src = src.strip_prefix('\u{feff}').unwrap_or(src);
    let mut starts = vec![0];
    starts.extend(
        src.bytes()
            .enumerate()
            .filter(|(_, b)| *b == b'\n')
            .map(|(i, _)| i + 1),
    );
    let lines = starts.len();
    let parsed = match parse_module(src) {
        Ok(p) => p,
        Err(e) => {
            let at = e.location.start().to_usize();
            let line = match starts.binary_search(&at) {
                Ok(i) => i + 1,
                Err(i) => i,
            };
            return PyResult {
                parse_error: Some((line, e.error.to_string())),
                lines,
                ..PyResult::default()
            };
        }
    };
    let normalized = path.replace('\\', "/");
    let mut scanner = Scan {
        src,
        starts,
        res: PyResult {
            lines,
            ..PyResult::default()
        },
        in_tests: normalized
            .split('/')
            .any(|part| part == "tests" || part.starts_with("test_")),
        in_migration: normalized.contains("/migrations/") || normalized.contains("/upgrades/"),
        loop_depth: 0,
        public_route: false,
        class_depth: 0,
        dynamic_sql_vars: HashSet::new(),
        managed_cursors: HashSet::new(),
    };
    scanner.visit_body(&parsed.syntax().body);
    let mut result = scanner.res;
    // One statement can match the same rule twice, such as a secret's name and its format.
    let mut seen = HashSet::new();
    result.hits.retain(|h| seen.insert((h.rule, h.line)));
    result
}

/// `__manifest__.py` is a Python dict literal. It is read from the AST and never executed.
pub fn parse_manifest(src: &str) -> Option<HashMap<String, Value>> {
    let parsed = parse_module(src.strip_prefix('\u{feff}').unwrap_or(src)).ok()?;
    for stmt in &parsed.syntax().body {
        if let Stmt::Expr(e) = stmt {
            if let Expr::Dict(d) = &*e.value {
                let mut out = HashMap::new();
                for item in &d.items {
                    let Some(key) = item.key.as_ref().and_then(str_value) else {
                        continue;
                    };
                    out.insert(key, to_value(&item.value));
                }
                return Some(out);
            }
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Bool(bool),
    List(Vec<String>),
    Other,
}

fn to_value(e: &Expr) -> Value {
    match e {
        Expr::StringLiteral(s) => Value::Str(s.value.to_str().to_string()),
        Expr::BooleanLiteral(b) => Value::Bool(b.value),
        Expr::List(l) => Value::List(l.elts.iter().filter_map(str_value).collect()),
        _ => Value::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(src: &str) -> Vec<&'static str> {
        rules_at("m/models/x.py", src)
    }

    fn rules_at(path: &str, src: &str) -> Vec<&'static str> {
        let r = scan(path, src);
        assert!(r.parse_error.is_none(), "{:?}", r.parse_error);
        r.hits.iter().map(|h| h.rule).collect()
    }

    #[test]
    fn dynamic_sql_is_flagged_in_every_form() {
        assert_eq!(rules("self.env.cr.execute(f\"select {x}\")"), ["PY001"]);
        assert_eq!(rules("cr.execute('select %s' % x)"), ["PY001"]);
        assert_eq!(rules("cr.execute('select ' + x)"), ["PY001"]);
        assert_eq!(rules("cr.execute('select {}'.format(x))"), ["PY001"]);
        assert_eq!(
            rules("def f():\n    q = f'select {x}'\n    cr.execute(q)\n"),
            ["PY001"]
        );
    }

    #[test]
    fn safe_sql_is_not_flagged() {
        assert!(rules("cr.execute('select %s', (x,))").is_empty());
        assert!(rules("cr.execute(SQL('select %s', x))").is_empty());
        assert!(rules("cr.execute(f'select id from {self._table}')").is_empty());
        assert!(rules("cr.execute('select id from %s' % self._table)").is_empty());
        assert!(rules("cr.execute(f'create view v as {self._select()}')").is_empty());
        assert!(rules("cr.execute(f'select {COLUMNS} from x')").is_empty());
        assert!(rules("cr.execute('select ' 'id')").is_empty());
        assert!(rules("cr.execute(f'select 1')").is_empty());
        assert!(
            rules("def f():\n    q = f'select {x}'\n    q = 'select 1'\n    cr.execute(q)\n")
                .is_empty()
        );
        assert!(rules("thing.execute(f'{x}')").is_empty());
    }

    #[test]
    fn public_route_sudo_and_csrf() {
        let src = "class C:\n    @http.route('/x', auth='public', csrf=False)\n    def x(self):\n        return request.env['a'].sudo().search([])\n";
        let r = rules(src);
        assert!(r.contains(&"PY002") && r.contains(&"PY003"), "{r:?}");
    }

    #[test]
    fn user_route_sudo_is_fine_and_webhook_json_is_fine() {
        assert!(rules(
            "class C:\n    @http.route('/x', auth='user')\n    def x(self):\n        self.sudo()\n"
        )
        .is_empty());
        assert!(rules("class C:\n    @http.route('/x', auth='public', type='jsonrpc', csrf=False)\n    def x(self):\n        pass\n").is_empty());
        assert!(rules("class C:\n    @http.route('/x', auth='public', csrf=False, methods=['GET'])\n    def x(self):\n        pass\n").is_empty());
    }

    #[test]
    fn dangerous_calls() {
        assert_eq!(rules("eval(code)"), ["PY004"]);
        assert!(rules("eval('1+1')").is_empty());
        assert!(rules("re.search(x, y)").is_empty());
        assert_eq!(rules("pickle.loads(b)"), ["PY005"]);
        assert_eq!(rules("yaml.load(b)"), ["PY005"]);
        assert!(rules("yaml.load(b, Loader=yaml.SafeLoader)").is_empty());
        assert_eq!(rules("subprocess.run(f'x {y}', shell=True)"), ["PY006"]);
        assert!(rules("subprocess.run(['x', y])").is_empty());
        assert_eq!(rules("os.system(cmd)"), ["PY006"]);
    }

    #[test]
    fn http_clients() {
        assert_eq!(rules("requests.get(u)"), ["PY011"]);
        assert_eq!(rules("requests.get(u, verify=False, timeout=5)"), ["PY007"]);
        assert!(rules("requests.post(u, timeout=5)").is_empty());
    }

    #[test]
    fn secrets_are_flagged_without_copying_the_value() {
        let r = scan("m/x.py", "API_KEY = 'abcd1234efgh5678'\n");
        assert_eq!(r.hits[0].rule, "PY008");
        assert!(!r.hits[0].detail.contains("abcd1234"));
        assert_eq!(rules("TOKEN_URL = 'https://x.io/oauth'").len(), 0);
        assert_eq!(rules("password = 'changeme12345'").len(), 0);
        assert_eq!(rules("KEY = 'sk_live_abc'"), ["PY008"]);
        assert!(rules("CERT = '-----BEGIN CERTIFICATE-----'").is_empty());
        assert_eq!(rules("K = '-----BEGIN RSA PRIVATE KEY-----'"), ["PY008"]);
        assert!(rules("DEMO_PRIVATE_KEY = 'abcd1234efgh5678demo'").is_empty());
    }

    #[test]
    fn commit_rules_understand_owned_cursors() {
        assert_eq!(rules("self.env.cr.commit()"), ["PY010"]);
        assert!(
            rules("def f(self):\n    with registry.cursor() as cr:\n        cr.commit()\n")
                .is_empty()
        );
        assert!(rules("def f(self):\n    cr = registry.cursor()\n    cr.commit()\n").is_empty());
    }

    #[test]
    fn orm_in_loops() {
        assert_eq!(
            rules("for x in y:\n    self.env['a'].search([])\n"),
            ["PY012"]
        );
        assert_eq!(rules("[self.env['a'].search([]) for x in y]"), ["PY012"]);
        assert!(rules("self.env['a'].search([])").is_empty());
        assert!(rules("for x in y:\n    re.search(a, b)\n").is_empty());
        // A loop outside a method does not count inside it.
        assert!(
            rules("for x in y:\n    def f(self):\n        self.env['a'].search([])\n").is_empty()
        );
    }

    #[test]
    fn tests_skip_noise_but_not_upgrade_rules() {
        assert!(rules_at("m/tests/test_x.py", "eval(code)").is_empty());
        assert_eq!(
            rules_at("m/tests/test_x.py", "ICP.get_param('a')"),
            ["UPG002"]
        );
        assert!(rules_at("test_base/models/x.py", "eval(code)").is_empty());
        assert!(scan(
            "test_base/models/x.py",
            "class A(models.Model):\n    _name = 'a.b'\n"
        )
        .models
        .is_empty());
    }

    #[test]
    fn old_migration_scripts_are_not_upgrade_work() {
        assert!(rules_at("m/migrations/9.0.2.0/pre.py", "import openerp").is_empty());
    }

    #[test]
    fn upgrade_rules() {
        assert_eq!(rules("from odoo.osv import expression"), ["UPG003"]);
        assert_eq!(rules("from odoo import osv"), ["UPG003"]);
        assert_eq!(rules("import openerp"), ["UPG014"]);
        assert_eq!(
            rules("env['ir.config_parameter'].get_param('a')"),
            ["UPG002"]
        );
        assert_eq!(rules("ICP.get_param('a')"), ["UPG002"]);
        assert!(rules("part.get_param('charset')").is_empty());
        assert_eq!(rules("x = fields.Float(group_operator='sum')"), ["UPG006"]);
        assert_eq!(
            rules("class A(models.Model):\n    def name_get(self):\n        pass\n"),
            ["UPG008"]
        );
        assert_eq!(
            rules("class A(models.Model):\n    _sql_constraints = []\n"),
            ["UPG009"]
        );
        assert_eq!(rules("self._cr"), ["UPG010"]);
        assert_eq!(rules("user.groups_id"), ["UPG011"]);
        assert_eq!(rules("env.search([('groups_id', '=', 1)])"), ["UPG011"]);
        assert_eq!(
            rules("class A:\n    @api.multi\n    def f(self):\n        pass\n"),
            ["UPG014"]
        );
        assert_eq!(rules("x.read_group([], [], [])"), ["UPG018"]);
        assert_eq!(rules("class C:\n    @http.route('/x', type='json', auth='user')\n    def x(self):\n        pass\n"), ["UPG020"]);
        assert!(rules("x._read_group([], [], [])").is_empty());
    }

    #[test]
    fn models_are_collected_and_extensions_are_not() {
        let r = scan("m/x.py", "class A(models.Model):\n    _name = 'a.b'\n\nclass B(models.Model):\n    _inherit = 'c.d'\n\nclass C(models.Model):\n    _name = 'e.f'\n    _inherit = 'e.f'\n\nclass D(models.Model):\n    _name = 'g.h'\n    _inherit = ['g.h', 'mail.thread']\n");
        assert_eq!(r.models, vec![("a.b".to_string(), 1)]);
    }

    #[test]
    fn silent_exceptions() {
        assert_eq!(rules("try:\n    x()\nexcept:\n    pass\n"), ["PY013"]);
        assert_eq!(
            rules("try:\n    x()\nexcept Exception:\n    pass\n"),
            ["PY013"]
        );
        assert!(rules("try:\n    x()\nexcept ValueError:\n    pass\n").is_empty());
    }

    #[test]
    fn syntax_errors_are_reported_with_a_line() {
        let r = scan("m/x.py", "x = 1\ndef (:\n");
        assert_eq!(r.parse_error.unwrap().0, 2);
    }

    #[test]
    fn bom_and_unicode_do_not_break_line_numbers() {
        let r = scan("m/x.py", "\u{feff}# ñandú\nprint('año')\neval(x)\n");
        assert_eq!(r.hits[0].line, 3);
    }

    #[test]
    fn manifest_is_read_without_executing_it() {
        let m = parse_manifest("# c\n{'name': 'X', 'version': '17.0.1', 'installable': False, 'depends': ['a', 'b'], 'x': 1 + 1}\n").unwrap();
        assert_eq!(m["version"], Value::Str("17.0.1".into()));
        assert_eq!(m["installable"], Value::Bool(false));
        assert_eq!(m["depends"], Value::List(vec!["a".into(), "b".into()]));
        assert_eq!(m["x"], Value::Other);
        assert!(parse_manifest("import os\nos.system('x')").is_none());
    }
}
