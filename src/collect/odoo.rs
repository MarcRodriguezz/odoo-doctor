//! Odoo business data, as read from SQL or the API. Both fill the same struct, so checks do not
//! care which one ran. Queries never select secret columns: where a secret matters, the database
//! computes a boolean about it and the value itself never leaves PostgreSQL.
use super::sql::SqlClient;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct OdooData {
    /// What provided the data, for the coverage section of the report.
    pub source: String,
    pub major: Option<u32>,
    pub version: Option<String>,
    pub modules: Vec<Module>,
    pub users: Vec<User>,
    pub crons: Vec<Cron>,
    pub mail: MailStats,
    pub mail_servers: Vec<MailServer>,
    pub params: BTreeMap<String, String>,
    pub open_acls: Vec<OpenAcl>,
    pub attachments: AttachmentStats,
    pub code_actions: Option<i64>,
    pub fetchmail_failing: Vec<String>,
    pub queue_jobs: Option<QueueStats>,
    pub ir_logging_errors: Option<i64>,
    /// Sections that could not be read, with the reason, so reports do not imply they are clean.
    pub gaps: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Module {
    pub name: String,
    pub state: String,
    pub version: String,
    pub author: String,
    pub demo: bool,
}

impl Module {
    pub fn is_vendor(&self) -> bool {
        is_vendor_author(&self.author)
    }
}

pub fn is_vendor_author(author: &str) -> bool {
    let a = author.to_ascii_lowercase();
    a.contains("odoo s.a") || a == "odoo" || a.contains("openerp s.a")
}

#[derive(Debug, Clone, Default)]
pub struct User {
    pub id: i64,
    pub login: String,
    pub active: bool,
    pub share: bool,
    pub is_admin: bool,
    pub days_since_login: Option<i64>,
    pub has_totp: Option<bool>,
    pub plaintext_password: Option<bool>,
    pub api_keys: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct Cron {
    pub name: String,
    pub active: bool,
    pub days_overdue: f64,
    pub interval: String,
    pub failure_count: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct MailStats {
    pub failed_30d: i64,
    pub stuck_outgoing: i64,
    pub oldest_stuck_hours: f64,
    pub available: bool,
}

#[derive(Debug, Clone, Default)]
pub struct MailServer {
    pub name: String,
    pub encryption: String,
}

#[derive(Debug, Clone, Default)]
pub struct OpenAcl {
    pub model: String,
    pub module: String,
    pub rights: String,
}

#[derive(Debug, Clone, Default)]
pub struct AttachmentStats {
    pub db_bytes: i64,
    pub db_count: i64,
    pub total_count: i64,
}

#[derive(Debug, Clone, Default)]
pub struct QueueStats {
    pub failed: i64,
    pub stuck: i64,
}

/// Configuration keys read from the database. An allowlist, because this table also holds secrets.
pub const SAFE_PARAMS: &[&str] = &[
    "web.base.url",
    "web.base.url.freeze",
    "auth_signup.invitation_scope",
    "auth_password_policy.minlength",
    "database.expiration_date",
    "database.expiration_reason",
    "ir_attachment.location",
];

pub fn major_of(version: &str) -> Option<u32> {
    let cleaned = version
        .trim()
        .trim_start_matches("saas~")
        .trim_start_matches("saas-");
    cleaned.split(['.', '-', '+']).next()?.parse().ok()
}

fn s(v: &Value, k: &str) -> String {
    match &v[k] {
        Value::String(x) => x.clone(),
        // Odoo keeps translated names as JSON: {"en_US": "..."}.
        Value::Object(m) => m
            .get("en_US")
            .or_else(|| m.values().next())
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}
fn i(v: &Value, k: &str) -> i64 {
    v[k].as_i64()
        .or_else(|| v[k].as_f64().map(|f| f as i64))
        .unwrap_or(0)
}
fn f(v: &Value, k: &str) -> f64 {
    v[k].as_f64().unwrap_or(0.0)
}
fn b(v: &Value, k: &str) -> bool {
    v[k].as_bool().unwrap_or(false)
}

/// Reads everything from SQL. A failing section is recorded as a gap, and the audit continues.
pub fn from_sql(sql: &mut SqlClient) -> Result<OdooData, String> {
    if !sql.has_table("ir_module_module") {
        return Err(format!(
            "database `{}` is not an Odoo database",
            sql.database()
        ));
    }
    let mut data = OdooData {
        source: format!("SQL ({})", sql.describe()),
        ..OdooData::default()
    };
    let gap = |name: &str, result: Result<(), String>, gaps: &mut Vec<String>| {
        if let Err(e) = result {
            gaps.push(format!("{name}: {e}"));
        }
    };
    let mut gaps = Vec::new();

    let r = read_modules(sql, &mut data);
    gap("modules", r, &mut gaps);
    let r = read_users(sql, &mut data);
    gap("users", r, &mut gaps);
    let r = read_crons(sql, &mut data);
    gap("scheduled actions", r, &mut gaps);
    let r = read_mail(sql, &mut data);
    gap("mail", r, &mut gaps);
    let r = read_params(sql, &mut data);
    gap("system parameters", r, &mut gaps);
    let r = read_acls(sql, &mut data);
    gap("access rules", r, &mut gaps);
    let r = read_attachments(sql, &mut data);
    gap("attachments", r, &mut gaps);
    let r = read_misc(sql, &mut data);
    gap("other", r, &mut gaps);
    data.gaps = gaps;
    Ok(data)
}

fn read_modules(sql: &mut SqlClient, data: &mut OdooData) -> Result<(), String> {
    let rows = sql.rows(
        "SELECT name, state, coalesce(latest_version, '') AS version, coalesce(author, '') AS author, \
         coalesce(demo, false) AS demo \
         FROM ir_module_module WHERE state NOT IN ('uninstalled', 'uninstallable') ORDER BY name",
    )?;
    data.modules = rows
        .iter()
        .map(|r| Module {
            name: s(r, "name"),
            state: s(r, "state"),
            version: s(r, "version"),
            author: s(r, "author"),
            demo: b(r, "demo"),
        })
        .collect();
    if let Some(base) = data.modules.iter().find(|m| m.name == "base") {
        data.major = major_of(&base.version);
        data.version = Some(base.version.clone());
    }
    Ok(())
}

fn read_users(sql: &mut SqlClient, data: &mut OdooData) -> Result<(), String> {
    let totp = sql.has_column("res_users", "totp_secret");
    let keys = sql.has_table("res_users_apikeys");
    let totp_sql = if totp {
        "(u.totp_secret IS NOT NULL AND u.totp_secret <> '') AS has_totp"
    } else {
        "NULL::boolean AS has_totp"
    };
    let keys_sql = if keys {
        "(SELECT count(*) FROM res_users_apikeys k WHERE k.user_id = u.id) AS api_keys"
    } else {
        "NULL::bigint AS api_keys"
    };
    // Membership follows implied groups, so an administrator through another group still counts.
    let query = format!(
        "WITH RECURSIVE admin_groups AS ( \
           SELECT res_id AS gid FROM ir_model_data WHERE module = 'base' AND name = 'group_system' AND model = 'res.groups' \
           UNION SELECT i.gid FROM res_groups_implied_rel i JOIN admin_groups a ON i.hid = a.gid \
         ) \
         SELECT u.id, u.login, u.active, coalesce(u.share, false) AS share, \
           EXISTS (SELECT 1 FROM res_groups_users_rel r JOIN admin_groups a ON a.gid = r.gid WHERE r.uid = u.id) AS is_admin, \
           (SELECT extract(day FROM now() - max(l.create_date)) FROM res_users_log l WHERE l.create_uid = u.id)::bigint AS days_since_login, \
           (u.password IS NOT NULL AND u.password <> '' AND u.password !~ '^\\$(pbkdf2|argon2|scrypt|bcrypt|2[aby]\\$)') AS plaintext_password, \
           {totp_sql}, {keys_sql} \
         FROM res_users u ORDER BY u.id"
    );
    let rows = sql.rows(&query)?;
    data.users = rows
        .iter()
        .map(|r| User {
            id: i(r, "id"),
            login: s(r, "login"),
            active: b(r, "active"),
            share: b(r, "share"),
            is_admin: b(r, "is_admin"),
            days_since_login: r["days_since_login"].as_i64(),
            has_totp: r["has_totp"].as_bool(),
            plaintext_password: r["plaintext_password"].as_bool(),
            api_keys: r["api_keys"].as_i64(),
        })
        .collect();
    Ok(())
}

fn read_crons(sql: &mut SqlClient, data: &mut OdooData) -> Result<(), String> {
    let failures = sql.has_column("ir_cron", "failure_count");
    let fail_sql = if failures {
        "failure_count"
    } else {
        "NULL::int AS failure_count"
    };
    let rows = sql.rows(&format!(
        "SELECT cron_name AS name, active, interval_number::text || ' ' || interval_type AS interval, \
         extract(epoch FROM (now() AT TIME ZONE 'UTC') - nextcall) / 86400.0 AS days_overdue, {fail_sql} FROM ir_cron ORDER BY id"
    ))?;
    data.crons = rows
        .iter()
        .map(|r| Cron {
            name: s(r, "name"),
            active: b(r, "active"),
            days_overdue: f(r, "days_overdue"),
            interval: s(r, "interval"),
            failure_count: r["failure_count"].as_i64(),
        })
        .collect();
    Ok(())
}

fn read_mail(sql: &mut SqlClient, data: &mut OdooData) -> Result<(), String> {
    if sql.has_table("ir_mail_server") {
        let rows = sql.rows("SELECT name, coalesce(smtp_encryption, 'none') AS encryption FROM ir_mail_server WHERE active ORDER BY id")?;
        data.mail_servers = rows
            .iter()
            .map(|r| MailServer {
                name: s(r, "name"),
                encryption: s(r, "encryption"),
            })
            .collect();
    }
    if !sql.has_table("mail_mail") {
        return Ok(());
    }
    let r = sql.one(
        "SELECT count(*) FILTER (WHERE state = 'exception' AND create_date > now() - interval '30 days') AS failed, \
           count(*) FILTER (WHERE state = 'outgoing' AND coalesce(scheduled_date, create_date) < (now() AT TIME ZONE 'UTC') - interval '1 hour') AS stuck, \
           coalesce(extract(epoch FROM (now() AT TIME ZONE 'UTC') - min(coalesce(scheduled_date, create_date)) FILTER (WHERE state = 'outgoing')) / 3600.0, 0) AS oldest \
         FROM mail_mail",
    )?;
    data.mail = MailStats {
        failed_30d: i(&r, "failed"),
        stuck_outgoing: i(&r, "stuck"),
        oldest_stuck_hours: f(&r, "oldest"),
        available: true,
    };
    Ok(())
}

fn read_params(sql: &mut SqlClient, data: &mut OdooData) -> Result<(), String> {
    let list = SAFE_PARAMS
        .iter()
        .map(|k| format!("'{k}'"))
        .collect::<Vec<_>>()
        .join(",");
    let rows = sql.rows(&format!(
        "SELECT key, value FROM ir_config_parameter WHERE key IN ({list})"
    ))?;
    for r in rows {
        data.params.insert(s(&r, "key"), s(&r, "value"));
    }
    Ok(())
}

fn read_acls(sql: &mut SqlClient, data: &mut OdooData) -> Result<(), String> {
    // ir_model_data maps each rule to its module, which separates custom rules from Odoo's own.
    let rows = if sql.has_table("ir_model_access") {
        sql.rows(
            "SELECT m.model, coalesce(d.module, '(created in the database)') AS module, \
               concat_ws(' ', CASE WHEN a.perm_write THEN 'write' END, CASE WHEN a.perm_create THEN 'create' END, CASE WHEN a.perm_unlink THEN 'delete' END) AS rights, \
               coalesce(mm.author, '') AS author \
             FROM ir_model_access a JOIN ir_model m ON m.id = a.model_id \
             LEFT JOIN ir_model_data d ON d.model = 'ir.model.access' AND d.res_id = a.id \
             LEFT JOIN ir_module_module mm ON mm.name = d.module \
             WHERE a.active AND a.group_id IS NULL AND (a.perm_write OR a.perm_create OR a.perm_unlink)",
        )?
    } else if sql.has_table("ir_access") {
        sql.rows(
            "SELECT m.model, coalesce(d.module, '(created in the database)') AS module, \
               a.operation AS rights, coalesce(mm.author, '') AS author \
             FROM ir_access a JOIN ir_model m ON m.id = a.model_id \
             LEFT JOIN ir_model_data d ON d.model = 'ir.access' AND d.res_id = a.id \
             LEFT JOIN ir_module_module mm ON mm.name = d.module \
             WHERE a.active AND a.group_id IS NULL AND a.operation ~ '[cud]' AND coalesce(a.domain, '') IN ('', '[]')",
        )?
    } else {
        Vec::new()
    };
    data.open_acls = rows
        .iter()
        .filter(|r| !is_vendor_author(&s(r, "author")))
        .map(|r| OpenAcl {
            model: s(r, "model"),
            module: s(r, "module"),
            rights: s(r, "rights"),
        })
        .collect();
    Ok(())
}

fn read_attachments(sql: &mut SqlClient, data: &mut OdooData) -> Result<(), String> {
    let r = sql.one(
        "SELECT count(*) AS total, count(*) FILTER (WHERE db_datas IS NOT NULL) AS db_count, \
         coalesce(sum(file_size) FILTER (WHERE db_datas IS NOT NULL), 0) AS db_bytes FROM ir_attachment",
    )?;
    data.attachments = AttachmentStats {
        db_bytes: i(&r, "db_bytes"),
        db_count: i(&r, "db_count"),
        total_count: i(&r, "total"),
    };
    Ok(())
}

fn read_misc(sql: &mut SqlClient, data: &mut OdooData) -> Result<(), String> {
    if sql.has_table("ir_act_server") {
        let r = sql.one(
            "SELECT count(*) AS n FROM ir_act_server a WHERE a.state = 'code' \
             AND NOT EXISTS (SELECT 1 FROM ir_model_data d WHERE d.model = 'ir.actions.server' AND d.res_id = a.id)",
        )?;
        data.code_actions = Some(i(&r, "n"));
    }
    if sql.has_table("fetchmail_server") && sql.has_column("fetchmail_server", "error_date") {
        let rows = sql.rows(
            "SELECT name FROM fetchmail_server WHERE active AND error_date IS NOT NULL AND error_date > now() - interval '7 days'",
        )?;
        data.fetchmail_failing = rows.iter().map(|r| s(r, "name")).collect();
    }
    if sql.has_table("queue_job") {
        let r = sql.one(
            "SELECT count(*) FILTER (WHERE state = 'failed') AS failed, \
             count(*) FILTER (WHERE state = 'started' AND date_started < (now() AT TIME ZONE 'UTC') - interval '1 hour') AS stuck FROM queue_job",
        )?;
        data.queue_jobs = Some(QueueStats {
            failed: i(&r, "failed"),
            stuck: i(&r, "stuck"),
        });
    }
    if sql.has_table("ir_logging") {
        let r = sql.one("SELECT count(*) AS n FROM ir_logging WHERE level IN ('ERROR', 'CRITICAL') AND create_date > now() - interval '7 days'")?;
        data.ir_logging_errors = Some(i(&r, "n"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_major_from_module_and_saas_versions() {
        assert_eq!(major_of("19.0.1.3"), Some(19));
        assert_eq!(major_of("saas~19.4"), Some(19));
        assert_eq!(major_of("20.0-20261102"), Some(20));
        assert_eq!(major_of(""), None);
    }

    #[test]
    fn vendor_detection_is_not_fooled_by_partial_names() {
        assert!(is_vendor_author("Odoo S.A."));
        assert!(is_vendor_author("Odoo"));
        assert!(!is_vendor_author("Odoo Community Association (OCA)"));
        assert!(!is_vendor_author("Acme"));
    }

    #[test]
    fn safe_params_exclude_secrets() {
        for key in SAFE_PARAMS {
            for word in ["secret", "passwd", "token", "enterprise_code", "uuid"] {
                assert!(!key.contains(word), "{key}");
            }
        }
    }

    #[test]
    fn translated_json_names_are_flattened() {
        let v = serde_json::json!({"name": {"en_US": "Hello", "es_ES": "Hola"}});
        assert_eq!(s(&v, "name"), "Hello");
    }
}
