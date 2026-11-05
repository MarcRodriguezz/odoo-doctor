//! Finds custom modules on the target and analyzes their source code.
pub mod python;
pub mod xml;

use crate::collect::odoo::is_vendor_author;
use crate::transport::Transport;
use python::Value;
use rayon::prelude::*;
use std::collections::{BTreeMap, HashSet};
use std::io::Read;

/// Largest file analyzed. Larger ones are generated data, not code a person wrote.
const MAX_FILE_BYTES: u64 = 3_000_000;

#[derive(Debug, Clone)]
pub struct Hit {
    pub rule: &'static str,
    pub file: String,
    pub line: usize,
    pub detail: String,
}

#[derive(Debug, Clone, Default)]
pub struct ScannedModule {
    pub name: String,
    pub version: Option<String>,
    pub license: Option<String>,
    pub installable: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CodeData {
    pub roots: Vec<String>,
    pub modules: Vec<ScannedModule>,
    pub hits: Vec<Hit>,
    pub py_files: usize,
    pub xml_files: usize,
    pub lines: usize,
    pub vendor_modules_skipped: usize,
    pub vendor_module_names: HashSet<String>,
    /// True when every path in `addons_path` was read, so absent modules really are absent.
    pub complete: bool,
    pub errors: Vec<String>,
}

struct SourceFile {
    path: String,
    bytes: Vec<u8>,
}

fn wanted(path: &str) -> bool {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    name.ends_with(".py") || name.ends_with(".xml") || name.ends_with(".csv")
}

fn excluded_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | "static" | "i18n" | "__pycache__" | "node_modules" | ".venv" | "venv" | "_vendor"
    )
}

fn read_local(root: &str) -> Result<Vec<SourceFile>, String> {
    let meta = std::fs::metadata(root).map_err(|e| format!("{root}: {e}"))?;
    if !meta.is_dir() {
        return Err(format!("{root}: not a directory"));
    }
    let mut files = Vec::new();
    let walker = walkdir::WalkDir::new(root).into_iter().filter_entry(|e| {
        !(e.file_type().is_dir() && e.depth() > 0 && excluded_dir(&e.file_name().to_string_lossy()))
    });
    for entry in walker.flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry
            .path()
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .replace('\\', "/");
        if !wanted(&path) || entry.metadata().map(|m| m.len()).unwrap_or(0) > MAX_FILE_BYTES {
            continue;
        }
        if let Ok(bytes) = std::fs::read(entry.path()) {
            files.push(SourceFile { path, bytes });
        }
    }
    Ok(files)
}

fn read_remote(transport: &Transport, root: &str) -> Result<Vec<SourceFile>, String> {
    let bytes = transport.read_tree(root)?;
    let mut archive = tar::Archive::new(bytes.as_slice());
    let mut files = Vec::new();
    for entry in archive.entries().map_err(|e| e.to_string())? {
        let Ok(mut entry) = entry else { continue };
        if !entry.header().entry_type().is_file() || entry.size() > MAX_FILE_BYTES {
            continue;
        }
        let Ok(path) = entry
            .path()
            .map(|p| p.to_string_lossy().trim_start_matches("./").to_string())
        else {
            continue;
        };
        if !wanted(&path) {
            continue;
        }
        let mut buf = Vec::with_capacity(entry.size() as usize);
        if entry.read_to_end(&mut buf).is_ok() {
            files.push(SourceFile { path, bytes: buf });
        }
    }
    Ok(files)
}

fn module_dir_of(path: &str) -> Option<&str> {
    let name = path.rsplit('/').next()?;
    if name == "__manifest__.py" || name == "__openerp__.py" {
        Some(path.rsplit_once('/').map_or("", |(d, _)| d))
    } else {
        None
    }
}

/// Splits CSV text into records. Quoted fields can span lines, and Odoo domains often do.
fn parse_csv(text: &str) -> Vec<(usize, Vec<String>)> {
    let mut records = Vec::new();
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut line = 1;
    let mut start_line = 1;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut current)),
            '\n' if !quoted => {
                fields.push(std::mem::take(&mut current));
                records.push((start_line, std::mem::take(&mut fields)));
                line += 1;
                start_line = line;
            }
            '\r' if !quoted => {}
            _ => {
                if c == '\n' {
                    line += 1;
                }
                current.push(c);
            }
        }
    }
    if !current.is_empty() || !fields.is_empty() {
        fields.push(current);
        records.push((start_line, fields));
    }
    records
}

/// Reads access CSVs. Returns the models they cover, and pushes findings for open rights.
fn scan_access_csv(file: &str, text: &str, hits: &mut Vec<Hit>) -> Vec<String> {
    let name = file.rsplit('/').next().unwrap_or(file);
    let is_old = name == "ir.model.access.csv";
    let is_new = name == "ir.access.csv";
    if !is_old && !is_new {
        return Vec::new();
    }
    let mut records = parse_csv(text).into_iter();
    let header: Vec<String> = records
        .next()
        .map(|(_, f)| f)
        .unwrap_or_default()
        .iter()
        .map(|h| h.trim().trim_start_matches('\u{feff}').to_string())
        .collect();
    let column = |wanted: &[&str]| header.iter().position(|h| wanted.contains(&h.as_str()));
    let model_col = column(&["model_id:id", "model_id/id", "model_id"]);
    let group_col = column(&["group_id:id", "group_id/id", "group_id"]);
    if is_old {
        hits.push(Hit {
            rule: "UPG001",
            file: file.to_string(),
            line: 1,
            detail: "ir.model.access.csv".to_string(),
        });
    }
    let write_cols: Vec<usize> = header
        .iter()
        .enumerate()
        .filter(|(_, h)| matches!(h.as_str(), "perm_write" | "perm_create" | "perm_unlink"))
        .map(|(i, _)| i)
        .collect();
    let operation = column(&["operation"]);
    let domain = column(&["domain"]);
    let mut models = Vec::new();
    for (line, fields) in records {
        if fields.iter().all(|f| f.trim().is_empty()) {
            continue;
        }
        let field = |i: Option<usize>| i.and_then(|i| fields.get(i)).map_or("", |s| s.trim());
        let model = field(model_col);
        if !model.is_empty() {
            models.push(
                model
                    .rsplit('.')
                    .next()
                    .filter(|_| model.contains(".model_"))
                    .unwrap_or(model)
                    .to_string(),
            );
        }
        if field(group_col).is_empty() {
            let grants_write = if is_old {
                write_cols
                    .iter()
                    .any(|i| fields.get(*i).is_some_and(|v| v.trim() == "1"))
            } else {
                field(operation).chars().any(|c| "cud".contains(c))
                    && matches!(field(domain), "" | "[]")
            };
            if grants_write {
                hits.push(Hit {
                    rule: "CSV001",
                    file: file.to_string(),
                    line,
                    detail: format!("{model}: write access with no group"),
                });
            }
        }
    }
    models
}

fn model_covered(model: &str, covered: &HashSet<String>) -> bool {
    covered.contains(model) || covered.contains(&format!("model_{}", model.replace('.', "_")))
}

/// Analyzes `roots`. Odoo's own modules are skipped unless `include_vendor` is set.
pub fn collect(
    transport: &Transport,
    roots: &[String],
    include_vendor: bool,
    complete: bool,
) -> CodeData {
    let mut data = CodeData {
        roots: roots.to_vec(),
        complete,
        ..CodeData::default()
    };
    let mut all: Vec<(String, SourceFile)> = Vec::new();
    for root in roots {
        let read = if transport.is_local() {
            read_local(root)
        } else {
            read_remote(transport, root)
        };
        match read {
            Ok(files) => all.extend(files.into_iter().map(|f| (root.clone(), f))),
            Err(e) => {
                data.complete = false;
                data.errors.push(e);
            }
        }
    }
    // Find modules, then keep only files inside a custom module.
    let mut modules: BTreeMap<(String, String), ScannedModule> = BTreeMap::new();
    let mut skipped_dirs: HashSet<(String, String)> = HashSet::new();
    for (root, file) in &all {
        let Some(dir) = module_dir_of(&file.path) else {
            continue;
        };
        let name = dir.rsplit('/').next().unwrap_or(dir);
        let name = if name.is_empty() {
            root.trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or("module")
        } else {
            name
        };
        let text = String::from_utf8_lossy(&file.bytes);
        let manifest = python::parse_manifest(&text).unwrap_or_default();
        let text_of = |k: &str| match manifest.get(k) {
            Some(Value::Str(s)) => Some(s.clone()),
            _ => None,
        };
        let author = text_of("author");
        // Odoo's Enterprise license marks vendor code, even in manifests with no author.
        let enterprise = text_of("license").as_deref() == Some("OEEL-1");
        if !include_vendor && (enterprise || author.as_deref().is_some_and(is_vendor_author)) {
            data.vendor_modules_skipped += 1;
            data.vendor_module_names.insert(name.to_string());
            skipped_dirs.insert((root.clone(), dir.to_string()));
            continue;
        }
        let installable = !matches!(manifest.get("installable"), Some(Value::Bool(false)));
        modules.insert(
            (root.clone(), dir.to_string()),
            ScannedModule {
                name: name.to_string(),
                version: text_of("version"),
                license: text_of("license"),
                installable,
            },
        );
    }
    let in_module = |root: &str, path: &str| -> Option<String> {
        let mut current = path.rsplit_once('/').map_or("", |(d, _)| d);
        loop {
            if modules.contains_key(&(root.to_string(), current.to_string())) {
                return Some(current.to_string());
            }
            if skipped_dirs.contains(&(root.to_string(), current.to_string())) {
                return None;
            }
            if current.is_empty() {
                return None;
            }
            current = current.rsplit_once('/').map_or("", |(d, _)| d);
        }
    };
    let files: Vec<(String, &SourceFile)> = all
        .iter()
        .filter(|(root, file)| in_module(root, &file.path).is_some())
        .map(|(root, file)| (root.clone(), file))
        .collect();

    // Stay gentle: this may be running on a production server.
    let threads = std::thread::available_parallelism()
        .map_or(2, |n| n.get())
        .div_ceil(2)
        .max(1);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .stack_size(16 * 1024 * 1024)
        .build()
        .ok();
    let analyze = || -> Vec<FileResult> {
        files
            .par_iter()
            .map(|(root, f)| analyze_file(root, f))
            .collect()
    };
    let results = match pool {
        Some(p) => p.install(analyze),
        None => analyze(),
    };

    let mut defined_models: Vec<(String, String, usize)> = Vec::new();
    let mut covered = HashSet::new();
    for result in results {
        data.lines += result.lines;
        data.py_files += usize::from(result.is_py);
        data.xml_files += usize::from(result.is_xml);
        data.hits.extend(result.hits);
        for (model, line) in result.models {
            defined_models.push((model, result.display.clone(), line));
        }
        covered.extend(result.acl_models);
    }
    for (model, file, line) in defined_models {
        if !model_covered(&model, &covered) {
            data.hits.push(Hit {
                rule: "MOD001",
                file,
                line,
                detail: model,
            });
        }
    }
    data.modules = modules.into_values().collect();
    data.hits
        .sort_by(|a, b| (a.rule, &a.file, a.line).cmp(&(b.rule, &b.file, b.line)));
    data
}

#[derive(Default)]
struct FileResult {
    display: String,
    hits: Vec<Hit>,
    models: Vec<(String, usize)>,
    acl_models: Vec<String>,
    lines: usize,
    is_py: bool,
    is_xml: bool,
}

fn analyze_file(root: &str, file: &SourceFile) -> FileResult {
    let text = String::from_utf8_lossy(&file.bytes);
    let display = format!("{}/{}", root.trim_end_matches('/'), file.path);
    let mut result = FileResult {
        display: display.clone(),
        ..FileResult::default()
    };
    // A crash on one strange file must cost that file only, never the whole audit.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if file.path.ends_with(".py") {
            result.is_py = true;
            let py = python::scan(&file.path, &text);
            result.lines = py.lines;
            result.models = py.models;
            result.hits = py.hits;
            if let Some((line, message)) = py.parse_error {
                result.hits.push(Hit {
                    rule: "MOD005",
                    file: String::new(),
                    line,
                    detail: first_chars(&message, 120),
                });
            }
        } else if file.path.ends_with(".xml") {
            result.is_xml = true;
            result.lines = text.lines().count();
            let (hits, error) = xml::scan(&text);
            result.hits = hits;
            if let Some((line, message)) = error {
                result.hits.push(Hit {
                    rule: "MOD005",
                    file: String::new(),
                    line,
                    detail: first_chars(&message, 120),
                });
            }
        } else if file.path.ends_with(".csv") {
            result.acl_models = scan_access_csv(&display, &text, &mut result.hits);
        }
    }));
    if outcome.is_err() {
        result.hits.push(Hit {
            rule: "MOD005",
            file: String::new(),
            line: 1,
            detail: "this file could not be analyzed".to_string(),
        });
    }
    for hit in &mut result.hits {
        if hit.file.is_empty() {
            hit.file.clone_from(&display);
        }
    }
    result
}

fn first_chars(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

/// Whether an addons path holds Odoo's own code, rather than something to audit.
pub fn is_core_path(path: &str) -> bool {
    let p = path.replace('\\', "/");
    p.ends_with("/odoo/addons")
        || p.ends_with("/odoo/odoo/addons")
        || p.contains("dist-packages/odoo")
        || p.contains("site-packages/odoo")
        || p.ends_with("/odoo/server/odoo/addons")
        || p.ends_with("/server/odoo/addons")
        || p.contains("/src/odoo/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &std::path::Path, rel: &str, text: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("odoo-doctor-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn skips_vendor_modules_and_files_outside_modules() {
        let dir = temp("vendor");
        write(
            &dir,
            "acme/__manifest__.py",
            "{'name': 'A', 'author': 'Acme', 'license': 'LGPL-3'}",
        );
        write(&dir, "acme/models/a.py", "eval(x)\n");
        write(
            &dir,
            "sale/__manifest__.py",
            "{'name': 'S', 'author': 'Odoo S.A.'}",
        );
        write(&dir, "sale/models/s.py", "eval(x)\n");
        write(&dir, "setup/tool.py", "eval(x)\n");
        write(
            &dir,
            "ent/__manifest__.py",
            "{'name': 'E', 'license': 'OEEL-1'}",
        );
        write(&dir, "ent/models/e.py", "eval(x)\n");
        let data = collect(
            &Transport::Local,
            &[dir.to_string_lossy().into_owned()],
            false,
            true,
        );
        assert_eq!(data.modules.len(), 1);
        assert_eq!(data.vendor_modules_skipped, 2);
        assert_eq!(data.hits.iter().filter(|h| h.rule == "PY004").count(), 1);
        assert!(data.hits[0].file.contains("acme"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_acl_is_found_across_modules() {
        let dir = temp("acl");
        write(&dir, "a/__manifest__.py", "{'name': 'A'}");
        write(&dir, "a/models/x.py", "class X(models.Model):\n    _name = 'a.x'\n\nclass Y(models.Model):\n    _name = 'a.y'\n");
        write(&dir, "b/__manifest__.py", "{'name': 'B'}");
        write(&dir, "b/security/ir.model.access.csv", "id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink\nx,x,a.model_a_x,base.group_user,1,1,1,1\n");
        let data = collect(
            &Transport::Local,
            &[dir.to_string_lossy().into_owned()],
            false,
            true,
        );
        let missing: Vec<_> = data
            .hits
            .iter()
            .filter(|h| h.rule == "MOD001")
            .map(|h| h.detail.as_str())
            .collect();
        assert_eq!(missing, ["a.y"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn access_csv_rules() {
        let mut hits = vec![];
        let models = scan_access_csv(
            "m/security/ir.model.access.csv",
            "id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink\na,a,model_x,,1,0,0,0\nb,b,model_y,,1,1,0,0\nc,c,model_z,base.group_user,1,1,1,1\n",
            &mut hits,
        );
        assert_eq!(models, ["model_x", "model_y", "model_z"]);
        let rules: Vec<_> = hits.iter().map(|h| (h.rule, h.line)).collect();
        assert_eq!(rules, [("UPG001", 1), ("CSV001", 3)]);
    }

    #[test]
    fn new_access_csv_format() {
        let mut hits = vec![];
        let models = scan_access_csv(
            "m/security/ir.access.csv",
            "id,name,model_id,group_id/id,operation,domain\na,a,x.y,,r,\nb,b,x.z,,crud,\nc,c,x.w,,crud,\"[('a', '=', 1)]\"\n",
            &mut hits,
        );
        assert_eq!(models, ["x.y", "x.z", "x.w"]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, 3);
        assert!(model_covered("x.y", &models.into_iter().collect()));
    }

    #[test]
    fn csv_records_can_span_lines() {
        let mut hits = vec![];
        let text = "id,name,model_id,group_id/id,operation,domain\nrule,r,x.y,,crud,\"\n  ['|', ('a', '=', 1)]\n\"\nopen,o,x.z,,crud,\n";
        let models = scan_access_csv("m/security/ir.access.csv", text, &mut hits);
        assert_eq!(models, ["x.y", "x.z"]);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].detail.starts_with("x.z"));
        assert_eq!(hits[0].line, 5);
    }

    #[test]
    fn core_paths_are_recognized() {
        assert!(is_core_path("/usr/lib/python3/dist-packages/odoo/addons"));
        assert!(is_core_path("/opt/odoo/odoo/addons"));
        assert!(!is_core_path("/mnt/extra-addons"));
        assert!(!is_core_path("/home/odoo/src/user"));
    }
}
