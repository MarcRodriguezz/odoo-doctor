//! SARIF 2.1.0, which GitHub code scanning reads. Only findings tied to a file are included,
//! because a server setting has no place in a pull request.
use crate::model::{Report, Severity};
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn relative_uri(path: &str) -> String {
    let path = path.replace('\\', "/");
    let cleaned = path.trim_start_matches("./");
    cleaned.trim_start_matches('/').to_string()
}

pub fn render(report: &Report) -> Value {
    let mut rules: BTreeMap<&str, Value> = BTreeMap::new();
    let mut results = Vec::new();
    for f in report.findings.iter().filter(|f| !f.locations.is_empty()) {
        rules.entry(&f.id).or_insert_with(|| {
            json!({
                "id": f.id,
                "name": f.id,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.why},
                "help": {"text": f.fix},
                "defaultConfiguration": {"level": level(f.severity)},
                "properties": {"tags": [format!("{:?}", f.category).to_lowercase()]}
            })
        });
        for location in &f.locations {
            results.push(json!({
                "ruleId": f.id,
                "level": level(f.severity),
                "message": {"text": format!("{} {}", f.title, f.fix)},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": relative_uri(&location.file)},
                    "region": {"startLine": location.line.max(1)}
                }}]
            }));
        }
    }
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "odoo-doctor",
                "version": report.tool_version,
                "informationUri": "https://github.com/MarcRodriguezz/odoo-doctor",
                "rules": rules.into_values().collect::<Vec<_>>()
            }},
            "results": results
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uris_are_relative_and_use_forward_slashes() {
        assert_eq!(relative_uri("./addons/x.py"), "addons/x.py");
        assert_eq!(relative_uri("/mnt/extra/x.py"), "mnt/extra/x.py");
        assert_eq!(relative_uri("addons\\x.py"), "addons/x.py");
    }

    #[test]
    fn levels_map_to_sarif() {
        assert_eq!(level(Severity::Critical), "error");
        assert_eq!(level(Severity::Medium), "warning");
        assert_eq!(level(Severity::Info), "note");
    }
}
