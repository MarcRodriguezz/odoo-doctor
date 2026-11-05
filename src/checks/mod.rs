//! Turns collected facts into findings. Every function here is pure, so each rule has a test
//! that needs no server.
pub mod catalog;

use crate::collect::conf::PasswordKind;
use crate::collect::Snapshot;
use crate::model::{Confidence, Finding, Location, Severity};
use catalog::rule;
use std::collections::{BTreeMap, BTreeSet};

/// Newest Odoo major version this release knows about. Update it with each Odoo release.
pub const LATEST_ODOO: u32 = 20;
/// Odoo supports the three most recent majors.
pub const OLDEST_SUPPORTED_ODOO: u32 = LATEST_ODOO - 2;
pub const OLDEST_SUPPORTED_PG: u32 = 14;

const MANAGED_BY_ODOO: &[&str] = &[
    "PG001", "PG002", "PG003", "PG007", "PG015", "EXT011", "EXT012", "HST001", "UPG017",
];

fn make(id: &str, summary: impl Into<String>, evidence: Vec<String>) -> Finding {
    let r = rule(id);
    Finding {
        id: r.id.to_string(),
        title: r.title.to_string(),
        severity: r.severity,
        confidence: r.confidence,
        category: r.category,
        layer: r.layer,
        summary: summary.into(),
        evidence,
        locations: Vec::new(),
        why: r.why.to_string(),
        fix: r.fix.to_string(),
    }
}

fn mib(bytes: i64) -> String {
    let m = bytes as f64 / 1_048_576.0;
    if m >= 1024.0 {
        format!("{:.1} GB", m / 1024.0)
    } else {
        format!("{m:.0} MB")
    }
}

pub fn run(s: &Snapshot) -> Vec<Finding> {
    let mut out = Vec::new();
    external(s, &mut out);
    config(s, &mut out);
    users(s, &mut out);
    operations(s, &mut out);
    postgres(s, &mut out);
    logs(s, &mut out);
    host(s, &mut out);
    code(s, &mut out);
    if s.managed {
        // On hosted Odoo, the operator controls these, and users cannot act on them.
        out.retain(|f| !MANAGED_BY_ODOO.contains(&f.id.as_str()) && !f.id.starts_with("CFG"));
    }
    out.sort_by(|a, b| a.severity.cmp(&b.severity).then_with(|| a.id.cmp(&b.id)));
    out
}

fn external(s: &Snapshot, out: &mut Vec<Finding>) {
    // A supported version check needs only the version, wherever it came from.
    if let Some(major) = s.major() {
        if major < OLDEST_SUPPORTED_ODOO {
            out.push(make(
                "EXT003",
                format!("This server runs Odoo {major}. Supported versions are {OLDEST_SUPPORTED_ODOO} to {LATEST_ODOO}."),
                vec![],
            ));
        }
    }
    let Some(e) = &s.external else { return };
    if !e.reachable {
        return;
    }
    if e.server_serie.is_none() {
        out.push(make(
            "EXT013",
            format!("{} did not answer as an Odoo server.", e.base_url),
            vec![],
        ));
    }
    if e.signup_open && !e.loopback {
        out.push(make("EXT010", "/web/signup accepts new accounts.", vec![]));
    }
    if e.loopback {
        return; // Exposure and transport findings make no sense on a local address.
    }
    if e.db_manager_open {
        out.push(make(
            "EXT001",
            format!(
                "{}/web/database/manager answered with the manager page.",
                e.base_url
            ),
            vec![],
        ));
    }
    if let Some(list) = &e.db_list {
        if !list.is_empty() {
            out.push(make(
                "EXT002",
                format!("{} database name(s) are listed publicly.", list.len()),
                list.iter().take(10).cloned().collect(),
            ));
        }
    }
    if !e.https {
        out.push(make(
            "EXT004",
            format!("{} uses plain HTTP.", e.base_url),
            vec![],
        ));
    }
    if e.https {
        if e.http_redirects_to_https == Some(false) {
            out.push(make(
                "EXT005",
                "The plain HTTP address serves the site, or redirects without going to HTTPS.",
                vec![],
            ));
        }
        if let Some(err) = &e.tls_error {
            out.push(make(
                "EXT006",
                "The certificate could not be verified.",
                vec![err.chars().take(200).collect()],
            ));
        }
        if let Some(cert) = &e.certificate {
            if cert.days_left < 21 {
                let mut f = make(
                    "EXT007",
                    format!("The certificate has {} day(s) left.", cert.days_left),
                    vec![cert.subject.clone()],
                );
                if cert.days_left < 7 {
                    f.severity = Severity::High;
                }
                out.push(f);
            }
        }
        if !e.hsts {
            out.push(make(
                "EXT008",
                "The login page has no Strict-Transport-Security header.",
                vec![],
            ));
        }
        if e.cookie_secure == Some(false) {
            out.push(make(
                "EXT009",
                "`session_id` is set without the Secure attribute.",
                vec![],
            ));
        }
    }
    for port in &e.open_ports {
        match port {
            8069 => out.push(make(
                "EXT011",
                format!("{}:8069 accepted a connection.", e.host),
                vec![],
            )),
            5432 => out.push(make(
                "EXT012",
                format!("{}:5432 accepted a connection.", e.host),
                vec![],
            )),
            _ => {}
        }
    }
}

fn config(s: &Snapshot, out: &mut Vec<Finding>) {
    let Some(c) = &s.conf else { return };
    match c.admin_passwd {
        PasswordKind::Weak => out.push(make(
            "CFG001",
            "`admin_passwd` is a common value or too short. The value is not shown here.",
            vec![],
        )),
        PasswordKind::Missing => out.push(make(
            "CFG002",
            "`admin_passwd` is not set in odoo.conf.",
            vec![],
        )),
        PasswordKind::Plaintext => {
            out.push(make("CFG003", "`admin_passwd` is not a hash.", vec![]))
        }
        PasswordKind::Hashed => {}
    }
    // Absent means True in Odoo.
    if c.flag("list_db").unwrap_or(true) {
        out.push(make("CFG004", "`list_db` is enabled.", vec![]));
    }
    if let Some(n) = s.db_count {
        if n > 1 && c.get("dbfilter").is_none() && c.get("db_name").is_none() {
            out.push(make(
                "CFG005",
                format!("{n} Odoo databases on this server, and no `dbfilter`."),
                vec![],
            ));
        }
    }
    let workers = c.int("workers").unwrap_or(0);
    if workers == 0 {
        out.push(make("CFG006", "`workers = 0`, or not set.", vec![]));
    }
    if let Some(mode) = c.get("dev_mode") {
        out.push(make("CFG007", format!("`dev_mode = {mode}`."), vec![]));
    }
    if let Some(level) = c.get("log_level") {
        if level.starts_with("debug") {
            out.push(make("CFG008", format!("`log_level = {level}`."), vec![]));
        }
    }
    if workers > 0 {
        let hard = c.int("limit_memory_hard");
        let time_real = c.int("limit_time_real");
        let mut issues = Vec::new();
        if hard.is_none() {
            issues.push("limit_memory_hard is not set".to_string());
        }
        if hard == Some(0) {
            issues.push("limit_memory_hard is disabled".to_string());
        }
        if time_real.is_some_and(|t| t <= 0 || t > 7200) {
            issues.push(format!("limit_time_real = {}", time_real.unwrap_or(0)));
        }
        if !issues.is_empty() {
            out.push(make(
                "CFG010",
                format!("{} limit(s) need attention.", issues.len()),
                issues,
            ));
        }
        if c.flag("proxy_mode") != Some(true) {
            out.push(make("CFG013", "`proxy_mode` is not enabled.", vec![]));
        }
    }
    if c.int("max_cron_threads") == Some(0) {
        out.push(make("CFG011", "`max_cron_threads = 0`.", vec![]));
    }
    if c.world_readable == Some(true) {
        out.push(make(
            "CFG012",
            format!("{} is readable by every user on the machine.", c.path),
            vec![],
        ));
    }
    // Odoo 20's default is local-only. Only warn when the current version is older or the target is 20+.
    let major = s.major();
    if major.is_some_and(|m| m < 20)
        && target_major(s).is_some_and(|t| t >= 20)
        && c.get("http_interface").is_none()
    {
        out.push(make(
            "UPG017",
            format!(
                "`http_interface` is not set, which matters when you move to Odoo {}.",
                target_major(s).unwrap_or(20)
            ),
            vec![],
        ));
    }
}

fn users(s: &Snapshot, out: &mut Vec<Finding>) {
    let Some(o) = &s.odoo else { return };
    let active: Vec<_> = o.users.iter().filter(|u| u.active).collect();
    let admins: Vec<_> = active
        .iter()
        .copied()
        .filter(|u| u.is_admin && u.id != 1 && !u.login.starts_with("__"))
        .collect();
    let internal = active.iter().filter(|u| !u.share).count();
    // A fixed limit is unfair to big companies, so it scales with the number of internal users.
    let limit = 5.max(internal / 10);
    if admins.len() > limit {
        out.push(make(
            "SEC001",
            format!(
                "{} active administrators, out of {internal} internal users.",
                admins.len()
            ),
            admins.iter().take(15).map(|u| u.login.clone()).collect(),
        ));
    }
    let stale: Vec<_> = admins
        .iter()
        .filter(|u| u.days_since_login.is_some_and(|d| d > 90))
        .collect();
    if !stale.is_empty() {
        out.push(make(
            "SEC002",
            format!(
                "{} administrator(s) have not logged in for over 90 days.",
                stale.len()
            ),
            stale
                .iter()
                .take(15)
                .map(|u| format!("{} ({} days)", u.login, u.days_since_login.unwrap_or(0)))
                .collect(),
        ));
    }
    let no_totp: Vec<_> = admins
        .iter()
        .filter(|u| u.has_totp == Some(false))
        .collect();
    if !no_totp.is_empty() {
        out.push(make(
            "SEC003",
            format!(
                "{} of {} administrators have no two-factor authentication.",
                no_totp.len(),
                admins.len()
            ),
            no_totp.iter().take(15).map(|u| u.login.clone()).collect(),
        ));
    }
    if active.iter().any(|u| u.login == "admin") {
        out.push(make(
            "SEC004",
            "An active user has the login `admin`.",
            vec![],
        ));
    }
    let external_admins: Vec<_> = active.iter().filter(|u| u.is_admin && u.share).collect();
    if !external_admins.is_empty() {
        out.push(make(
            "SEC005",
            format!(
                "{} portal or public user(s) have administrator rights.",
                external_admins.len()
            ),
            external_admins.iter().map(|u| u.login.clone()).collect(),
        ));
    }
    let plain = o
        .users
        .iter()
        .filter(|u| u.plaintext_password == Some(true))
        .count();
    if plain > 0 {
        out.push(make(
            "SEC006",
            format!("{plain} user(s) have a password that is not a recognized hash."),
            vec![],
        ));
    }
    let with_keys: Vec<_> = admins
        .iter()
        .filter(|u| u.api_keys.unwrap_or(0) > 0)
        .collect();
    if !with_keys.is_empty() {
        out.push(make(
            "SEC007",
            format!("{} administrator(s) have API keys.", with_keys.len()),
            with_keys
                .iter()
                .take(15)
                .map(|u| format!("{} ({} key(s))", u.login, u.api_keys.unwrap_or(0)))
                .collect(),
        ));
    }
    if !o.open_acls.is_empty() {
        out.push(make(
            "SEC008",
            format!(
                "{} custom access rule(s) grant write rights with no group.",
                o.open_acls.len()
            ),
            o.open_acls
                .iter()
                .take(20)
                .map(|a| format!("{}: {} (module {})", a.model, a.rights, a.module))
                .collect(),
        ));
    }
    let insecure: Vec<_> = o
        .mail_servers
        .iter()
        .filter(|m| m.encryption == "none" || m.encryption.is_empty())
        .collect();
    if !insecure.is_empty() {
        out.push(make(
            "SEC009",
            format!("{} active mail server(s) do not encrypt.", insecure.len()),
            insecure.iter().map(|m| m.name.clone()).collect(),
        ));
    }
    if let Some(url) = o.params.get("web.base.url") {
        if url.starts_with("http://") && !url.contains("localhost") && !url.contains("127.0.0.1") {
            out.push(make("SEC010", format!("web.base.url = {url}"), vec![]));
        }
    }
    let signup_installed = o
        .modules
        .iter()
        .any(|m| m.name == "auth_signup" && m.state == "installed");
    if signup_installed
        && o.params
            .get("auth_signup.invitation_scope")
            .map(String::as_str)
            == Some("b2c")
    {
        out.push(make("SEC011", "auth_signup.invitation_scope = b2c", vec![]));
    }
    if o.modules
        .iter()
        .any(|m| m.name == "auth_password_policy" && m.state == "installed")
    {
        if let Some(length) = o
            .params
            .get("auth_password_policy.minlength")
            .and_then(|v| v.parse::<i64>().ok())
        {
            if length < 8 {
                out.push(make(
                    "SEC012",
                    format!("Minimum password length is {length}."),
                    vec![],
                ));
            }
        }
    }
    if o.users.iter().any(|u| u.id == 1 && u.active) {
        out.push(make("SEC013", "The account with id 1 is active.", vec![]));
    }
    if let Some(n) = o.code_actions {
        if n > 20 {
            out.push(make(
                "SEC014",
                format!("{n} server actions with code were created in the database."),
                vec![],
            ));
        }
    }
    let demo: Vec<_> = o
        .modules
        .iter()
        .filter(|m| m.demo && m.state == "installed")
        .collect();
    if !demo.is_empty() {
        out.push(make(
            "SEC015",
            format!("{} module(s) were installed with demo data.", demo.len()),
            demo.iter().take(8).map(|m| m.name.clone()).collect(),
        ));
    }
    if let Some(date) = o.params.get("database.expiration_date") {
        if let Some(days) = days_until(date) {
            if days < 30 {
                out.push(make(
                    "SEC016",
                    format!("The subscription expires in {days} day(s) ({date})."),
                    vec![],
                ));
            }
        }
    }
}

fn days_until(stamp: &str) -> Option<i64> {
    let date = stamp.get(..10)?;
    let mut parts = date.split('-');
    let (y, m, d): (i32, u8, u8) = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    let target = time::Date::from_calendar_date(y, time::Month::try_from(m).ok()?, d).ok()?;
    Some((target - time::OffsetDateTime::now_utc().date()).whole_days())
}

fn operations(s: &Snapshot, out: &mut Vec<Finding>) {
    let Some(o) = &s.odoo else { return };
    let failing: Vec<_> = o
        .crons
        .iter()
        .filter(|c| c.failure_count.unwrap_or(0) > 0)
        .collect();
    if !failing.is_empty() {
        out.push(make(
            "OPS001",
            format!(
                "{} scheduled action(s) have recent failures.",
                failing.len()
            ),
            failing
                .iter()
                .take(15)
                .map(|c| format!("{} ({} failure(s))", c.name, c.failure_count.unwrap_or(0)))
                .collect(),
        ));
    }
    let overdue: Vec<_> = o
        .crons
        .iter()
        .filter(|c| c.active && c.days_overdue > allowed_delay_days(&c.interval))
        .collect();
    if !overdue.is_empty() {
        out.push(make(
            "OPS002",
            format!("{} active scheduled action(s) are overdue.", overdue.len()),
            overdue
                .iter()
                .take(15)
                .map(|c| {
                    format!(
                        "{} ({:.0} days late, runs every {})",
                        c.name, c.days_overdue, c.interval
                    )
                })
                .collect(),
        ));
    }
    if o.mail.available {
        if o.mail.failed_30d > 0 {
            out.push(make(
                "OPS003",
                format!("{} email(s) failed in the last 30 days.", o.mail.failed_30d),
                vec![],
            ));
        }
        if o.mail.stuck_outgoing > 0 {
            out.push(make(
                "OPS004",
                format!(
                    "{} email(s) are stuck. The oldest has waited {:.0} hours.",
                    o.mail.stuck_outgoing, o.mail.oldest_stuck_hours
                ),
                vec![],
            ));
        }
    }
    let pending: Vec<_> = o
        .modules
        .iter()
        .filter(|m| matches!(m.state.as_str(), "to install" | "to upgrade" | "to remove"))
        .collect();
    if !pending.is_empty() {
        out.push(make(
            "OPS005",
            format!("{} module(s) are in a pending state.", pending.len()),
            pending
                .iter()
                .take(20)
                .map(|m| format!("{}: {}", m.name, m.state))
                .collect(),
        ));
    }
    if o.attachments.db_bytes > 200 * 1024 * 1024 {
        out.push(make(
            "OPS006",
            format!(
                "{} in {} attachments is stored inside PostgreSQL.",
                mib(o.attachments.db_bytes),
                o.attachments.db_count
            ),
            vec![],
        ));
    }
    if !o.fetchmail_failing.is_empty() {
        out.push(make(
            "OPS007",
            format!(
                "{} incoming server(s) failed in the last 7 days.",
                o.fetchmail_failing.len()
            ),
            o.fetchmail_failing.clone(),
        ));
    }
    if let Some(q) = &o.queue_jobs {
        if q.failed + q.stuck > 0 {
            out.push(make(
                "OPS008",
                format!("{} failed and {} stuck job(s).", q.failed, q.stuck),
                vec![],
            ));
        }
    }
    if let Some(n) = o.ir_logging_errors {
        if n >= 50 {
            out.push(make(
                "OPS009",
                format!("{n} errors in ir_logging in the last 7 days."),
                vec![],
            ));
        }
    }
}

/// How late a cron may be before it counts: twice its interval, and at least a day.
fn allowed_delay_days(interval: &str) -> f64 {
    let mut parts = interval.split_whitespace();
    let count: f64 = parts.next().and_then(|n| n.parse().ok()).unwrap_or(1.0);
    let unit = match parts.next().unwrap_or("days") {
        "minutes" => 1.0 / 1440.0,
        "hours" => 1.0 / 24.0,
        "days" => 1.0,
        "weeks" => 7.0,
        "months" => 31.0,
        _ => 1.0,
    };
    (count * unit * 2.0).max(1.0)
}

fn postgres(s: &Snapshot, out: &mut Vec<Finding>) {
    let Some(p) = &s.pg else { return };
    if p.major > 0 && p.major < OLDEST_SUPPORTED_PG {
        out.push(make(
            "PG001",
            format!("PostgreSQL {} is end of life.", p.version),
            vec![],
        ));
    }
    if p.shared_buffers_mb > 0 && p.shared_buffers_mb <= 128 && p.db_size_bytes > 500 * 1024 * 1024
    {
        out.push(make(
            "PG002",
            format!(
                "`shared_buffers` is {} MB for a database of {}.",
                p.shared_buffers_mb,
                mib(p.db_size_bytes)
            ),
            vec![],
        ));
    }
    // A ratio from barely started statistics means nothing.
    if let Some(hit) = p.cache_hit_pct {
        if hit < 95.0 && p.stats_age_days.unwrap_or(0) >= 1 {
            out.push(make(
                "PG003",
                format!(
                    "Cache hit ratio is {hit:.1}%. A healthy Odoo database is usually above 99%."
                ),
                vec![],
            ));
        }
    }
    if p.max_connections > 0 && p.connections * 100 / p.max_connections >= 80 {
        out.push(make(
            "PG004",
            format!(
                "{} of {} connections are in use.",
                p.connections, p.max_connections
            ),
            vec![],
        ));
    }
    if !p.long_transactions.is_empty() {
        out.push(make(
            "PG005",
            format!(
                "{} transaction(s) have been open for over 5 minutes.",
                p.long_transactions.len()
            ),
            p.long_transactions
                .iter()
                .map(|t| {
                    format!(
                        "{:.0} minutes, state: {}",
                        t.minutes,
                        if t.state.is_empty() {
                            "unknown"
                        } else {
                            &t.state
                        }
                    )
                })
                .collect(),
        ));
    }
    if p.blocked > 0 {
        out.push(make(
            "PG006",
            format!("{} session(s) are waiting on locks right now.", p.blocked),
            vec![],
        ));
    }
    if p.settings.get("autovacuum").map(String::as_str) == Some("off") {
        out.push(make("PG007", "`autovacuum = off`.", vec![]));
    }
    if p.xid_age > 1_000_000_000 {
        out.push(make(
            "PG008",
            format!(
                "Transaction ID age is {}. The hard limit is about 2.1 billion.",
                p.xid_age
            ),
            vec![],
        ));
    }
    if !p.dead_tables.is_empty() {
        out.push(make(
            "PG009",
            format!("{} table(s) have many dead rows.", p.dead_tables.len()),
            p.dead_tables
                .iter()
                .map(|t| format!("{}: {} dead, {} live", t.name, t.dead, t.live))
                .collect(),
        ));
    }
    if !p.seq_tables.is_empty() {
        out.push(make(
            "PG010",
            format!(
                "{} large table(s) are read mainly by sequential scan.",
                p.seq_tables.len()
            ),
            p.seq_tables
                .iter()
                .map(|t| {
                    format!(
                        "{}: {} rows, {} scans, {} rows read per scan",
                        t.name, t.live, t.seq_scan, t.avg_seq_read
                    )
                })
                .collect(),
        ));
    }
    if !p.fk_no_index.is_empty() {
        out.push(make(
            "PG011",
            format!(
                "{} foreign key column(s) have no index.",
                p.fk_no_index.len()
            ),
            p.fk_no_index.clone(),
        ));
    }
    // Index usage needs a long observation window to mean anything.
    if !p.unused_indexes.is_empty() && p.stats_age_days.is_none_or(|d| d >= 14) {
        let total: i64 = p.unused_indexes.iter().map(|(_, b)| b).sum();
        out.push(make(
            "PG012",
            format!(
                "{} unused index(es) take {}.",
                p.unused_indexes.len(),
                mib(total)
            ),
            p.unused_indexes
                .iter()
                .map(|(n, b)| format!("{n}: {}", mib(*b)))
                .collect(),
        ));
    }
    if !p.invalid_indexes.is_empty() {
        out.push(make(
            "PG013",
            format!("{} invalid index(es).", p.invalid_indexes.len()),
            p.invalid_indexes.clone(),
        ));
    }
    if p.has_stat_statements {
        if p.slow_queries.iter().any(|q| q.mean_ms > 200.0) {
            out.push(make(
                "PG014",
                "The queries below use the most database time.".to_string(),
                p.slow_queries
                    .iter()
                    .map(|q| format!("{:.0} ms × {} calls: {}", q.mean_ms, q.calls, q.text))
                    .collect(),
            ));
        }
    } else {
        out.push(make(
            "PG015",
            "`pg_stat_statements` is not installed in this database.",
            vec![],
        ));
    }
    if p.is_superuser && s.pg_role_is_odoos {
        out.push(make(
            "CFG009",
            "The role Odoo connects with is a PostgreSQL superuser.",
            vec![],
        ));
    }
}

fn logs(s: &Snapshot, out: &mut Vec<Finding>) {
    let Some(l) = &s.logs else { return };
    if l.errors >= 5 {
        out.push(make(
            "LOG001",
            format!("{} errors in the last {} log lines.", l.errors, l.lines),
            l.signatures
                .iter()
                .map(|(sig, n)| format!("{n} × {sig}"))
                .collect(),
        ));
    }
    if !l.worker_kills.is_empty() {
        out.push(make(
            "LOG002",
            format!("{} worker limit event(s) found.", l.worker_kills.len()),
            l.worker_kills.clone(),
        ));
    }
    if l.concurrency_errors >= 3 {
        out.push(make(
            "LOG003",
            format!("{} deadlock or serialization errors.", l.concurrency_errors),
            vec![],
        ));
    }
}

fn host(s: &Snapshot, out: &mut Vec<Finding>) {
    let Some(h) = &s.host else { return };
    if let Some(used) = h.disk_used_pct {
        if used >= 85 {
            let mut f = make(
                "HST001",
                format!("{} is {used}% full.", h.disk_path),
                vec![],
            );
            if used >= 95 {
                f.severity = Severity::Critical;
            }
            out.push(f);
        }
    }
}

/// `(rule, removed in, removed or only deprecated)`. Verified against the source of Odoo 17, 19 and 20.
const UPGRADE_RULES: &[(&str, u32, bool)] = &[
    ("UPG001", 20, true),
    ("UPG002", 20, true),
    ("UPG003", 20, true),
    ("UPG004", 17, true),
    ("UPG005", 18, true),
    ("UPG006", 20, true),
    ("UPG007", 18, true),
    ("UPG008", 18, true),
    ("UPG009", 19, false),
    ("UPG010", 19, false),
    ("UPG011", 19, true),
    ("UPG012", 19, true),
    ("UPG013", 19, true),
    ("UPG014", 16, true),
    ("UPG015", 20, false),
    ("UPG016", 19, false),
    ("UPG018", 19, false),
    ("UPG020", 19, false),
];

pub fn target_major(s: &Snapshot) -> Option<u32> {
    s.target_major
        .or_else(|| s.major().map(|m| (m + 1).min(LATEST_ODOO)))
}

fn module_of<'a>(file: &'a str, code: &'a crate::code::CodeData) -> &'a str {
    code.modules
        .iter()
        .filter(|m| file.contains(&format!("/{}/", m.name)))
        .max_by_key(|m| m.name.len())
        .map_or("(unknown)", |m| m.name.as_str())
}

fn code(s: &Snapshot, out: &mut Vec<Finding>) {
    let Some(c) = &s.code else { return };
    let major = s.major();
    let target = target_major(s).unwrap_or(LATEST_ODOO);
    let mut grouped: BTreeMap<&str, Vec<&crate::code::Hit>> = BTreeMap::new();
    for hit in &c.hits {
        grouped.entry(hit.rule).or_default().push(hit);
    }
    let mut upgrade_modules: BTreeSet<&str> = BTreeSet::new();
    for (id, hits) in grouped {
        let upgrade = UPGRADE_RULES.iter().find(|(r, _, _)| *r == id);
        let mut finding = make(id, String::new(), Vec::new());
        finding.locations = hits
            .iter()
            .map(|h| Location {
                file: h.file.clone(),
                line: h.line,
            })
            .collect();
        let mut details: Vec<String> = Vec::new();
        for h in &hits {
            if !details.contains(&h.detail) && details.len() < 8 {
                details.push(h.detail.clone());
            }
        }
        finding.evidence = details;
        let modules: BTreeSet<&str> = hits.iter().map(|h| module_of(&h.file, c)).collect();
        // Code in a module that is not installed cannot cause harm until someone installs it.
        let dormant = s.odoo.as_ref().is_some_and(|o| {
            !o.modules.is_empty()
                && modules.iter().all(|m| {
                    !o.modules
                        .iter()
                        .any(|x| x.name == *m && x.state == "installed")
                })
        });
        if let Some((_, removed_in, removed)) = upgrade {
            if *removed_in > target {
                continue;
            }
            upgrade_modules.extend(modules.iter().copied());
            let already = major.is_some_and(|m| m >= *removed_in);
            finding.summary = match (already, removed) {
                (true, true) => format!("{} occurrence(s) in {} module(s). This is already incompatible with your Odoo {}.", hits.len(), modules.len(), major.unwrap_or(0)),
                (false, true) => format!("{} occurrence(s) in {} module(s). This must change before you move to Odoo {removed_in}.", hits.len(), modules.len()),
                (_, false) => format!("{} occurrence(s) in {} module(s). Deprecated since Odoo {removed_in}.", hits.len(), modules.len()),
            };
            if !already {
                // It is a to-do for the migration, and not a fault in production today.
                finding.severity = match finding.severity {
                    Severity::Critical | Severity::High => Severity::Medium,
                    Severity::Medium => Severity::Low,
                    other => other,
                };
            }
        } else {
            finding.summary = format!(
                "{} occurrence(s) in {} module(s).",
                hits.len(),
                modules.len()
            );
        }
        if dormant {
            finding
                .summary
                .push_str(" None of these modules is installed.");
            finding.severity = match finding.severity {
                Severity::Critical | Severity::High => Severity::Medium,
                Severity::Medium | Severity::Low => Severity::Low,
                Severity::Info => Severity::Info,
            };
        }
        out.push(finding);
    }
    for module in &c.modules {
        if module.license.is_none() {
            let mut f = out.iter_mut().find(|f| f.id == "MOD002");
            match f.as_mut() {
                Some(existing) => existing.evidence.push(module.name.clone()),
                None => out.push(make("MOD002", String::new(), vec![module.name.clone()])),
            }
        }
    }
    if let Some(f) = out.iter_mut().find(|f| f.id == "MOD002") {
        f.summary = format!("{} module(s) have no license key.", f.evidence.len());
    }
    if let Some(m) = major {
        let stale: Vec<String> = c
            .modules
            .iter()
            .filter(|md| md.installable)
            .filter_map(|md| {
                let v = md.version.as_deref()?;
                // Only `series.x.y.z` versions state a series. `1.0` says nothing either way.
                let has_series = v.matches('.').count() >= 3;
                let series = crate::collect::odoo::major_of(v)?;
                (has_series && series != m).then(|| format!("{} ({v})", md.name))
            })
            .collect();
        if !stale.is_empty() {
            out.push(make(
                "MOD003",
                format!(
                    "{} module(s) declare a different Odoo series than this server ({m}).",
                    stale.len()
                ),
                stale.into_iter().take(20).collect(),
            ));
        }
    }
    if c.complete {
        if let Some(o) = &s.odoo {
            let known: BTreeSet<&str> = c
                .modules
                .iter()
                .map(|m| m.name.as_str())
                .chain(c.vendor_module_names.iter().map(String::as_str))
                .collect();
            let missing: Vec<String> = o
                .modules
                .iter()
                .filter(|m| {
                    m.state == "installed"
                        && !m.is_vendor()
                        && !m.author.is_empty()
                        && !known.contains(m.name.as_str())
                })
                .map(|m| m.name.clone())
                .collect();
            if !missing.is_empty() {
                out.push(make(
                    "MOD004",
                    format!(
                        "{} installed module(s) were not found in the scanned paths.",
                        missing.len()
                    ),
                    missing.into_iter().take(20).collect(),
                ));
            }
        }
    }
    if !upgrade_modules.is_empty() {
        out.push(make(
            "UPG019",
            format!(
                "{} of {} custom module(s) need work to reach Odoo {target}.",
                upgrade_modules.len(),
                c.modules.len()
            ),
            upgrade_modules
                .iter()
                .take(30)
                .map(|m| m.to_string())
                .collect(),
        ));
    }
    // Findings inferred from patterns are never promoted to certain.
    debug_assert!(out
        .iter()
        .all(|f| f.confidence == rule(&f.id).confidence || f.confidence == Confidence::Certain));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::{CodeData, Hit, ScannedModule};
    use crate::collect::conf;
    use crate::collect::external::ExternalData;
    use crate::collect::odoo::{Cron, MailStats, Module, OdooData, User};
    use crate::collect::pg::PgData;

    fn ids(s: &Snapshot) -> Vec<String> {
        run(s).into_iter().map(|f| f.id).collect()
    }

    fn has(s: &Snapshot, id: &str) -> bool {
        ids(s).iter().any(|i| i == id)
    }

    fn public_site() -> ExternalData {
        ExternalData {
            base_url: "https://erp.example.com".into(),
            host: "erp.example.com".into(),
            https: true,
            reachable: true,
            server_serie: Some("19.0".into()),
            hsts: true,
            cookie_secure: Some(true),
            http_redirects_to_https: Some(true),
            ..ExternalData::default()
        }
    }

    #[test]
    fn a_well_configured_site_has_no_external_findings() {
        let s = Snapshot {
            external: Some(public_site()),
            ..Snapshot::default()
        };
        assert!(ids(&s).is_empty(), "{:?}", ids(&s));
    }

    #[test]
    fn exposure_is_reported_on_public_hosts_but_not_on_local_ones() {
        let mut e = public_site();
        e.https = false;
        e.db_manager_open = true;
        e.db_list = Some(vec!["prod".into()]);
        e.open_ports = vec![5432, 8069];
        let public = Snapshot {
            external: Some(e.clone()),
            ..Snapshot::default()
        };
        for id in ["EXT001", "EXT002", "EXT004", "EXT011", "EXT012"] {
            assert!(has(&public, id), "{id}");
        }
        e.loopback = true;
        let local = Snapshot {
            external: Some(e),
            ..Snapshot::default()
        };
        for id in ["EXT001", "EXT002", "EXT004", "EXT011", "EXT012"] {
            assert!(!has(&local, id), "{id}");
        }
    }

    #[test]
    fn unsupported_versions_are_flagged_from_the_version_alone() {
        let mut e = public_site();
        e.server_serie = Some("16.0".into());
        assert!(has(
            &Snapshot {
                external: Some(e),
                ..Snapshot::default()
            },
            "EXT003"
        ));
        let mut e = public_site();
        e.server_serie = Some(format!("{OLDEST_SUPPORTED_ODOO}.0"));
        assert!(!has(
            &Snapshot {
                external: Some(e),
                ..Snapshot::default()
            },
            "EXT003"
        ));
    }

    #[test]
    fn certificate_severity_grows_as_it_nears_expiry() {
        let mut e = public_site();
        e.certificate = Some(crate::tls::CertInfo {
            days_left: 3,
            subject: "x".into(),
        });
        let f = run(&Snapshot {
            external: Some(e),
            ..Snapshot::default()
        });
        assert_eq!(f[0].id, "EXT007");
        assert_eq!(f[0].severity, Severity::High);
    }

    fn conf_with(text: &str) -> Snapshot {
        Snapshot {
            conf: Some(conf::parse("/etc/odoo/odoo.conf", text)),
            ..Snapshot::default()
        }
    }

    #[test]
    fn config_rules() {
        let s = conf_with("[options]\nadmin_passwd = admin\nlist_db = True\nworkers = 0\ndev_mode = reload\nlog_level = debug\nmax_cron_threads = 0\n");
        for id in ["CFG001", "CFG004", "CFG006", "CFG007", "CFG008", "CFG011"] {
            assert!(has(&s, id), "{id}");
        }
    }

    #[test]
    fn a_good_config_is_clean() {
        let s = conf_with("[options]\nadmin_passwd = $pbkdf2-sha512$600000$a$b\nlist_db = False\nworkers = 5\nproxy_mode = True\nlimit_memory_hard = 2684354560\nlimit_time_real = 120\nlog_level = info\n");
        assert!(ids(&s).is_empty(), "{:?}", ids(&s));
    }

    #[test]
    fn findings_never_contain_the_master_password() {
        let s = conf_with("[options]\nadmin_passwd = verysecretadmin\nworkers = 0\n");
        let text = serde_json::to_string(&run(&s)).unwrap();
        assert!(!text.contains("verysecretadmin"));
    }

    fn user(id: i64, login: &str, admin: bool) -> User {
        User {
            id,
            login: login.into(),
            active: true,
            is_admin: admin,
            ..User::default()
        }
    }

    #[test]
    fn admin_count_scales_with_company_size() {
        let mut users: Vec<User> = (2..=8).map(|i| user(i, &format!("a{i}"), true)).collect();
        let small = OdooData {
            users: users.clone(),
            ..OdooData::default()
        };
        assert!(has(
            &Snapshot {
                odoo: Some(small),
                ..Snapshot::default()
            },
            "SEC001"
        ));
        users.extend((100..300).map(|i| user(i, &format!("u{i}"), false)));
        let big = OdooData {
            users,
            ..OdooData::default()
        };
        assert!(!has(
            &Snapshot {
                odoo: Some(big),
                ..Snapshot::default()
            },
            "SEC001"
        ));
    }

    #[test]
    fn user_rules() {
        let mut stale = user(5, "old@x.io", true);
        stale.days_since_login = Some(200);
        stale.has_totp = Some(false);
        stale.api_keys = Some(2);
        let mut portal = user(6, "ext@x.io", true);
        portal.share = true;
        let mut plain = user(7, "plain@x.io", false);
        plain.plaintext_password = Some(true);
        let system = user(1, "__system__", true);
        let named_admin = user(8, "admin", false);
        let odoo = OdooData {
            users: vec![stale, portal, plain, system, named_admin],
            ..OdooData::default()
        };
        let s = Snapshot {
            odoo: Some(odoo),
            ..Snapshot::default()
        };
        for id in [
            "SEC002", "SEC003", "SEC004", "SEC005", "SEC006", "SEC007", "SEC013",
        ] {
            assert!(has(&s, id), "{id}");
        }
    }

    #[test]
    fn cron_delay_depends_on_the_interval() {
        assert_eq!(allowed_delay_days("10 minutes"), 1.0);
        assert_eq!(allowed_delay_days("1 weeks"), 14.0);
        assert_eq!(allowed_delay_days("1 months"), 62.0);
        let cron = |days_overdue, interval: &str| Cron {
            name: "c".into(),
            active: true,
            days_overdue,
            interval: interval.into(),
            failure_count: None,
        };
        let monthly = OdooData {
            crons: vec![cron(5.0, "1 months")],
            ..OdooData::default()
        };
        assert!(!has(
            &Snapshot {
                odoo: Some(monthly),
                ..Snapshot::default()
            },
            "OPS002"
        ));
        let hourly = OdooData {
            crons: vec![cron(5.0, "1 hours")],
            ..OdooData::default()
        };
        assert!(has(
            &Snapshot {
                odoo: Some(hourly),
                ..Snapshot::default()
            },
            "OPS002"
        ));
    }

    #[test]
    fn inactive_crons_are_not_overdue() {
        let cron = Cron {
            name: "c".into(),
            active: false,
            days_overdue: 500.0,
            interval: "1 hours".into(),
            failure_count: None,
        };
        let odoo = OdooData {
            crons: vec![cron],
            ..OdooData::default()
        };
        assert!(!has(
            &Snapshot {
                odoo: Some(odoo),
                ..Snapshot::default()
            },
            "OPS002"
        ));
    }

    #[test]
    fn mail_and_modules() {
        let odoo = OdooData {
            mail: MailStats {
                failed_30d: 2,
                stuck_outgoing: 1,
                oldest_stuck_hours: 5.0,
                available: true,
            },
            modules: vec![Module {
                name: "x".into(),
                state: "to upgrade".into(),
                ..Module::default()
            }],
            ..OdooData::default()
        };
        let s = Snapshot {
            odoo: Some(odoo),
            ..Snapshot::default()
        };
        for id in ["OPS003", "OPS004", "OPS005"] {
            assert!(has(&s, id), "{id}");
        }
    }

    #[test]
    fn postgres_rules_respect_their_preconditions() {
        let base = PgData {
            major: 16,
            has_stat_statements: true,
            ..PgData::default()
        };
        assert!(ids(&Snapshot {
            pg: Some(base.clone()),
            ..Snapshot::default()
        })
        .is_empty());
        // Young statistics do not produce unused-index findings.
        let mut young = base.clone();
        young.unused_indexes = vec![("i".into(), 50 << 20)];
        young.stats_age_days = Some(1);
        assert!(!has(
            &Snapshot {
                pg: Some(young),
                ..Snapshot::default()
            },
            "PG012"
        ));
        let mut old = base.clone();
        old.unused_indexes = vec![("i".into(), 50 << 20)];
        old.stats_age_days = Some(30);
        assert!(has(
            &Snapshot {
                pg: Some(old),
                ..Snapshot::default()
            },
            "PG012"
        ));
        let mut broken = base;
        broken.major = 12;
        broken.max_connections = 100;
        broken.connections = 90;
        broken.settings.insert("autovacuum".into(), "off".into());
        broken.xid_age = 1_500_000_000;
        broken.blocked = 1;
        let s = Snapshot {
            pg: Some(broken),
            ..Snapshot::default()
        };
        for id in ["PG001", "PG004", "PG006", "PG007", "PG008"] {
            assert!(has(&s, id), "{id}");
        }
    }

    fn code_snapshot(major: u32, target: Option<u32>, rule_id: &'static str) -> Snapshot {
        let code = CodeData {
            modules: vec![ScannedModule {
                name: "acme".into(),
                license: Some("LGPL-3".into()),
                installable: true,
                ..ScannedModule::default()
            }],
            hits: vec![Hit {
                rule: rule_id,
                file: "/a/acme/x.py".into(),
                line: 3,
                detail: "d".into(),
            }],
            ..CodeData::default()
        };
        let odoo = OdooData {
            major: Some(major),
            ..OdooData::default()
        };
        Snapshot {
            code: Some(code),
            odoo: Some(odoo),
            target_major: target,
            ..Snapshot::default()
        }
    }

    #[test]
    fn upgrade_rules_follow_the_version_path() {
        // Not relevant yet: removed in 20, and the target is 19.
        assert!(!has(&code_snapshot(18, Some(19), "UPG001"), "UPG001"));
        // A to-do for the migration: downgraded to medium.
        let f = run(&code_snapshot(19, None, "UPG001"));
        let finding = f.iter().find(|f| f.id == "UPG001").unwrap();
        assert_eq!(finding.severity, Severity::Medium);
        assert!(finding.summary.contains("before you move to Odoo 20"));
        // Already broken on the current version: keeps its severity.
        let f = run(&code_snapshot(20, None, "UPG001"));
        let finding = f.iter().find(|f| f.id == "UPG001").unwrap();
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.summary.contains("already incompatible"));
    }

    #[test]
    fn code_in_uninstalled_modules_is_downgraded() {
        let mut installed = code_snapshot(19, None, "PY001");
        let module = |state: &str| Module {
            name: "acme".into(),
            state: state.into(),
            ..Module::default()
        };
        installed.odoo.as_mut().unwrap().modules = vec![module("installed")];
        assert_eq!(
            run(&installed)
                .iter()
                .find(|f| f.id == "PY001")
                .unwrap()
                .severity,
            Severity::High
        );
        let mut dormant = code_snapshot(19, None, "PY001");
        dormant.odoo.as_mut().unwrap().modules = vec![module("uninstalled")];
        let findings = run(&dormant);
        let finding = findings.iter().find(|f| f.id == "PY001").unwrap();
        assert_eq!(finding.severity, Severity::Medium);
        assert!(finding
            .summary
            .contains("None of these modules is installed"));
    }

    #[test]
    fn a_summary_counts_modules_needing_upgrade_work() {
        let s = code_snapshot(19, None, "UPG002");
        let f = run(&s);
        let summary = f.iter().find(|f| f.id == "UPG019").unwrap();
        assert!(summary.summary.starts_with("1 of 1"), "{}", summary.summary);
    }

    #[test]
    fn a_non_upgrade_rule_is_not_counted_as_upgrade_work() {
        assert!(!has(&code_snapshot(19, None, "PY001"), "UPG019"));
    }

    #[test]
    fn every_upgrade_rule_exists_in_the_catalog() {
        for (id, _, _) in UPGRADE_RULES {
            assert_eq!(rule(id).category, crate::model::Category::Upgrade);
        }
    }

    #[test]
    fn missing_source_needs_a_complete_scan() {
        let odoo = OdooData {
            major: Some(19),
            modules: vec![Module {
                name: "ghost".into(),
                state: "installed".into(),
                author: "Acme".into(),
                ..Module::default()
            }],
            ..OdooData::default()
        };
        let partial = Snapshot {
            odoo: Some(odoo.clone()),
            code: Some(CodeData::default()),
            ..Snapshot::default()
        };
        assert!(!has(&partial, "MOD004"));
        let complete = Snapshot {
            odoo: Some(odoo),
            code: Some(CodeData {
                complete: true,
                ..CodeData::default()
            }),
            ..Snapshot::default()
        };
        assert!(has(&complete, "MOD004"));
    }

    #[test]
    fn manifest_versions_only_count_when_they_state_a_series() {
        let module = |version: &str| ScannedModule {
            name: "m".into(),
            version: Some(version.into()),
            license: Some("x".into()),
            installable: true,
        };
        let snap = |version: &str| Snapshot {
            code: Some(CodeData {
                modules: vec![module(version)],
                ..CodeData::default()
            }),
            odoo: Some(OdooData {
                major: Some(19),
                ..OdooData::default()
            }),
            ..Snapshot::default()
        };
        assert!(has(&snap("17.0.1.0.0"), "MOD003"));
        assert!(!has(&snap("19.0.1.0.0"), "MOD003"));
        assert!(!has(&snap("1.0"), "MOD003"));
    }

    #[test]
    fn hosted_servers_do_not_get_findings_only_the_operator_can_fix() {
        let mut s = conf_with("[options]\nadmin_passwd = admin\nworkers = 0\n");
        s.pg = Some(PgData {
            major: 12,
            has_stat_statements: false,
            ..PgData::default()
        });
        s.managed = true;
        let found = ids(&s);
        assert!(
            !found
                .iter()
                .any(|i| i.starts_with("CFG") || i == "PG001" || i == "PG015"),
            "{found:?}"
        );
    }

    #[test]
    fn a_manual_postgres_url_does_not_blame_odoo_for_its_role() {
        let pg = PgData {
            major: 16,
            is_superuser: true,
            has_stat_statements: true,
            ..PgData::default()
        };
        let mine = Snapshot {
            pg: Some(pg.clone()),
            ..Snapshot::default()
        };
        assert!(has(&mine, "CFG009"));
        let other = Snapshot {
            pg: Some(pg),
            pg_role_is_odoos: false,
            ..Snapshot::default()
        };
        assert!(!has(&other, "CFG009"));
    }

    #[test]
    fn findings_are_sorted_by_severity() {
        let s = conf_with("[options]\nadmin_passwd = admin\nworkers = 0\nlog_level = debug\n");
        let f = run(&s);
        assert!(f.windows(2).all(|w| w[0].severity <= w[1].severity));
    }
}
