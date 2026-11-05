//! Builds the report and writes it out in each format.
pub mod sarif;
pub mod terminal;

use crate::checks;
use crate::collect::Snapshot;
use crate::model::{self, Finding, Layer, LayerState, LayerStatus, Report};
use time::format_description::well_known::Rfc3339;

/// Fewer areas than this and a report shows its score, but gives no grade.
const MIN_LAYERS_FOR_GRADE: usize = 4;

fn bytes_label(bytes: i64) -> String {
    let gb = bytes as f64 / 1_073_741_824.0;
    if gb >= 1.0 {
        format!("{gb:.1} GB")
    } else {
        format!("{:.0} MB", bytes as f64 / 1_048_576.0)
    }
}

fn layer_status(s: &Snapshot, layer: Layer) -> LayerStatus {
    let skipped = s
        .skipped
        .iter()
        .find(|(l, _)| *l == layer)
        .map(|(_, reason)| reason.clone());
    let (state, detail) = match layer {
        Layer::External => match &s.external {
            Some(e) if e.reachable && e.loopback => (
                LayerState::Partial,
                format!(
                    "{}: local address, so exposure checks were skipped",
                    e.base_url
                ),
            ),
            Some(e) if e.reachable => (LayerState::Ran, e.base_url.clone()),
            Some(e) => (
                LayerState::Skipped,
                format!("{} could not be reached", e.base_url),
            ),
            None => (LayerState::Skipped, skipped.unwrap_or_default()),
        },
        Layer::Config => match &s.conf {
            Some(c) => (LayerState::Ran, c.path.clone()),
            None => (LayerState::Skipped, skipped.unwrap_or_default()),
        },
        Layer::Database => match &s.odoo {
            Some(o) if o.gaps.is_empty() => (LayerState::Ran, o.source.clone()),
            Some(o) => (
                LayerState::Partial,
                format!("{}. Not read: {}", o.source, o.gaps.join("; ")),
            ),
            None => (LayerState::Skipped, skipped.unwrap_or_default()),
        },
        Layer::Postgres => match &s.pg {
            Some(p) if p.gaps.is_empty() => (LayerState::Ran, format!("PostgreSQL {}", p.version)),
            Some(p) => (
                LayerState::Partial,
                format!("PostgreSQL {}. Not read: {}", p.version, p.gaps.join("; ")),
            ),
            None => (LayerState::Skipped, skipped.unwrap_or_default()),
        },
        Layer::Code => match &s.code {
            Some(c) if c.errors.is_empty() => (
                LayerState::Ran,
                format!(
                    "{} custom modules, {} Python and {} XML files, {} lines",
                    c.modules.len(),
                    c.py_files,
                    c.xml_files,
                    c.lines
                ),
            ),
            Some(c) => (
                LayerState::Partial,
                format!(
                    "{} custom modules. Could not read: {}",
                    c.modules.len(),
                    c.errors.join("; ")
                ),
            ),
            None => (LayerState::Skipped, skipped.unwrap_or_default()),
        },
        Layer::Logs => match &s.logs {
            Some(l) => (LayerState::Ran, format!("{}: {} lines", l.source, l.lines)),
            None => (LayerState::Skipped, skipped.unwrap_or_default()),
        },
        Layer::Host => match &s.host {
            Some(h) => (LayerState::Ran, format!("disk usage of {}", h.disk_path)),
            None => (LayerState::Skipped, skipped.unwrap_or_default()),
        },
    };
    LayerStatus {
        layer,
        label: layer.label().to_string(),
        state,
        detail,
    }
}

fn facts(s: &Snapshot) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(o) = &s.odoo {
        let active = o.users.iter().filter(|u| u.active).count();
        let internal = o.users.iter().filter(|u| u.active && !u.share).count();
        let admins = o
            .users
            .iter()
            .filter(|u| u.active && u.is_admin && u.id != 1)
            .count();
        out.push((
            "Active users".to_string(),
            format!("{active} ({internal} internal, {admins} administrators)"),
        ));
        let installed = o.modules.iter().filter(|m| m.state == "installed").count();
        let custom = o
            .modules
            .iter()
            .filter(|m| m.state == "installed" && !m.is_vendor())
            .count();
        out.push((
            "Installed modules".to_string(),
            format!("{installed} ({custom} not by Odoo S.A.)"),
        ));
        out.push((
            "Scheduled actions".to_string(),
            format!("{} active", o.crons.iter().filter(|c| c.active).count()),
        ));
        if o.attachments.total_count > 0 {
            out.push((
                "Attachments".to_string(),
                format!("{}", o.attachments.total_count),
            ));
        }
    }
    if let Some(p) = &s.pg {
        out.push(("PostgreSQL".to_string(), p.version.clone()));
        out.push(("Database size".to_string(), bytes_label(p.db_size_bytes)));
        out.push((
            "Connections".to_string(),
            format!("{} of {}", p.connections, p.max_connections),
        ));
        if let Some(hit) = p.cache_hit_pct {
            out.push(("Cache hit ratio".to_string(), format!("{hit:.1}%")));
        }
        if let Some(largest) = p.big_tables.first() {
            out.push((
                "Largest table".to_string(),
                format!("{} ({})", largest.name, bytes_label(largest.bytes)),
            ));
        }
    }
    if let Some(c) = &s.conf {
        if let Some(w) = c.int("workers") {
            out.push(("Workers".to_string(), w.to_string()));
        }
    }
    out
}

/// `j***@example.com`. Enough to recognize a colleague, not enough to identify a stranger.
fn mask_login(login: &str) -> String {
    match login.split_once('@') {
        Some((user, domain)) => format!("{}***@{domain}", user.chars().next().unwrap_or('*')),
        None => format!("{}***", login.chars().next().unwrap_or('*')),
    }
}

/// Replaces `word` only where it stands alone, so masking the login `admin` leaves
/// `admin_passwd` readable and masking the database `lab` leaves `lab_order` alone.
fn replace_whole_word(text: &mut String, word: &str, mask: &str) {
    let is_word = |c: char| c.is_alphanumeric() || c == '_' || c == '-';
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    let mut previous: Option<char> = None;
    while let Some(index) = rest.find(word) {
        let before = rest[..index].chars().next_back().or(previous);
        let after = rest[index + word.len()..].chars().next();
        let standalone = !before.is_some_and(is_word) && !after.is_some_and(is_word);
        out.push_str(&rest[..index]);
        out.push_str(if standalone { mask } else { word });
        previous = word.chars().next_back();
        rest = &rest[index + word.len()..];
    }
    out.push_str(rest);
    *text = out;
}

fn redact(report: &mut Report, s: &Snapshot) {
    let mut secrets: Vec<(String, String)> = Vec::new();
    if let Some(o) = &s.odoo {
        for user in &o.users {
            if user.login.len() >= 3 {
                secrets.push((user.login.clone(), mask_login(&user.login)));
            }
        }
    }
    let mut databases: Vec<String> = s.database.iter().cloned().collect();
    if let Some(list) = s.external.as_ref().and_then(|e| e.db_list.as_ref()) {
        databases.extend(list.iter().cloned());
    }
    for db in databases {
        if db.len() >= 2 {
            secrets.push((db, "<database>".to_string()));
        }
    }
    // Longest first, so a login containing another one is replaced whole.
    secrets.sort_by_key(|(k, _)| std::cmp::Reverse(k.len()));
    let clean = |text: &mut String| {
        for (secret, mask) in &secrets {
            replace_whole_word(text, secret, mask);
        }
    };
    if report.database.is_some() {
        report.database = Some("<database>".to_string());
    }
    for finding in &mut report.findings {
        clean(&mut finding.summary);
        finding.evidence.iter_mut().for_each(clean);
    }
    report.layers.iter_mut().for_each(|l| clean(&mut l.detail));
    report.redacted = true;
}

pub fn build(s: &Snapshot, findings: Vec<Finding>, redacted: bool) -> Report {
    let score = model::score(&findings);
    let now = time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default();
    let target = s
        .external
        .as_ref()
        .map(|e| e.base_url.clone())
        .or_else(|| s.code.as_ref().map(|c| c.roots.join(", ")))
        .unwrap_or_else(|| s.deployment.clone());
    let layers: Vec<LayerStatus> = Layer::ALL.iter().map(|l| layer_status(s, *l)).collect();
    let examined = layers
        .iter()
        .filter(|l| l.state != LayerState::Skipped)
        .count();
    // A clean result from a narrow look must not read like a clean bill of health.
    let limited = (examined < MIN_LAYERS_FOR_GRADE).then(|| {
        format!(
            "Only {examined} of {} areas could be checked, so this is not a grade for the whole system.",
            layers.len()
        )
    });
    let mut report = Report {
        schema_version: 1,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        generated_at: now,
        target,
        deployment: s.deployment.clone(),
        odoo_version: s.version_label(),
        database: s.database.clone(),
        upgrade_target: s.code.as_ref().and_then(|_| checks::target_major(s)),
        score,
        grade: if limited.is_some() {
            "–".to_string()
        } else {
            model::grade(score, &findings).to_string()
        },
        limited,
        counts: model::count(&findings),
        categories: model::category_scores(&findings),
        layers,
        facts: facts(s),
        findings,
        redacted: false,
    };
    if redacted {
        redact(&mut report, s);
    }
    report
}

/// Escapes text, then turns `backticks` into `<code>`. Escaping comes first, so values
/// from the audited system can never inject markup.
fn code_spans(text: &str) -> minijinja::Value {
    let escaped = text
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;");
    let mut out = String::with_capacity(escaped.len());
    for (index, part) in escaped.split('`').enumerate() {
        if index % 2 == 1 {
            out.push_str("<code>");
            out.push_str(part);
            out.push_str("</code>");
        } else {
            out.push_str(part);
        }
    }
    if escaped.matches('`').count() % 2 == 1 {
        // An unmatched backtick is ordinary text, and must not leave a tag open.
        return minijinja::Value::from_safe_string(escaped);
    }
    minijinja::Value::from_safe_string(out)
}

pub fn html(report: &Report) -> Result<String, String> {
    let mut env = minijinja::Environment::new();
    env.add_filter("code", code_spans);
    env.add_template("report.html", include_str!("report.html"))
        .map_err(|e| e.to_string())?;
    let template = env.get_template("report.html").map_err(|e| e.to_string())?;
    template
        .render(minijinja::context! { r => report })
        .map_err(|e| format!("{e:#}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::conf;
    use crate::collect::odoo::{OdooData, User};

    fn sample() -> (Snapshot, Vec<Finding>) {
        let admin = |id: i64, login: &str| User {
            id,
            login: login.into(),
            active: true,
            is_admin: true,
            has_totp: Some(false),
            ..User::default()
        };
        let odoo = OdooData {
            users: vec![admin(2, "alice@acme.com"), admin(3, "bob@acme.com")],
            ..OdooData::default()
        };
        let s = Snapshot {
            deployment: "Docker (x)".into(),
            database: Some("acme_prod".into()),
            conf: Some(conf::parse(
                "/etc/odoo/odoo.conf",
                "[options]\nworkers = 0\nadmin_passwd = admin\n",
            )),
            odoo: Some(odoo),
            ..Snapshot::default()
        };
        let findings = checks::run(&s);
        (s, findings)
    }

    #[test]
    fn redaction_masks_logins_and_databases_everywhere() {
        let (s, findings) = sample();
        let report = build(&s, findings, true);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("alice@acme.com"));
        assert!(!json.contains("acme_prod"));
        assert!(json.contains("a***@acme.com"));
        assert!(report.redacted);
    }

    #[test]
    fn a_narrow_audit_gets_no_grade_even_when_clean() {
        let narrow = build(&Snapshot::default(), vec![], false);
        assert_eq!(narrow.score, 100);
        assert_eq!(narrow.grade, "–");
        assert!(narrow
            .limited
            .as_deref()
            .unwrap()
            .starts_with("Only 0 of 7"));
        let page = html(&narrow).unwrap();
        assert!(page.contains("not a grade for the whole system"));
        assert!(!page.contains("grade A"));
    }

    #[test]
    fn a_broad_audit_gets_a_grade() {
        let s = Snapshot {
            conf: Some(conf::parse("/x", "[options]\n")),
            odoo: Some(OdooData::default()),
            pg: Some(crate::collect::pg::PgData::default()),
            logs: Some(crate::collect::logs::LogData::default()),
            ..Snapshot::default()
        };
        let report = build(&s, vec![], false);
        assert_eq!(report.grade, "A");
        assert!(report.limited.is_none());
    }

    #[test]
    fn redaction_only_touches_whole_words() {
        let mut text = "admin_passwd, oddoc-lab-19, lab_order, the lab database, admin".to_string();
        replace_whole_word(&mut text, "admin", "a***");
        replace_whole_word(&mut text, "lab", "<database>");
        assert_eq!(
            text,
            "admin_passwd, oddoc-lab-19, lab_order, the <database> database, a***"
        );
    }

    #[test]
    fn code_spans_escape_before_formatting() {
        assert_eq!(
            code_spans("set `a<b`").to_string(),
            "set <code>a&lt;b</code>"
        );
        assert_eq!(
            code_spans("<script>`x`").to_string(),
            "&lt;script&gt;<code>x</code>"
        );
        assert_eq!(code_spans("odd ` tick").to_string(), "odd ` tick");
    }

    #[test]
    fn without_redaction_logins_are_visible_for_the_person_fixing_them() {
        let (s, findings) = sample();
        let json = serde_json::to_string(&build(&s, findings, false)).unwrap();
        assert!(json.contains("alice@acme.com"));
    }

    #[test]
    fn coverage_states_why_a_layer_did_not_run() {
        let s = Snapshot {
            skipped: vec![(Layer::Postgres, "no access".into())],
            ..Snapshot::default()
        };
        let status = layer_status(&s, Layer::Postgres);
        assert_eq!(status.state, LayerState::Skipped);
        assert_eq!(status.detail, "no access");
    }

    #[test]
    fn html_renders_and_escapes_values() {
        let (s, mut findings) = sample();
        findings[0].summary = "<script>alert(1)</script>".to_string();
        findings[0]
            .evidence
            .push("'\"<img src=x onerror=y>".to_string());
        let page = html(&build(&s, findings, false)).unwrap();
        assert!(page.contains("<!doctype html>"));
        assert!(!page.contains("<script>alert(1)</script>"));
        assert!(!page.contains("<img src=x"));
        assert!(page.contains("&lt;script&gt;alert(1)"));
    }

    #[test]
    fn html_renders_with_nothing_found() {
        let page = html(&build(&Snapshot::default(), vec![], false)).unwrap();
        assert!(page.contains("No problems found"));
    }
}
