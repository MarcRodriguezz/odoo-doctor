//! Odoo's external API, for deployments with no database access (Odoo Online, some Odoo.sh setups).
//! Only the methods in `ALLOWED_METHODS` can be sent, which keeps this client read-only by construction.
use super::odoo::{major_of, Cron, MailServer, MailStats, Module, OdooData, User, SAFE_PARAMS};
use serde_json::{json, Value};
use std::time::Duration;

pub const ALLOWED_METHODS: &[&str] = &["search_read", "search_count", "fields_get"];

pub struct ApiClient {
    agent: ureq::Agent,
    base: String,
    database: String,
    login: String,
    key: String,
    /// JSON-2 exists from Odoo 19 on. Older versions use JSON-RPC.
    json2: bool,
    uid: Option<i64>,
}

fn days_since(timestamp: &str) -> Option<i64> {
    // Odoo format: 2026-11-05 11:29:25
    let date = timestamp.get(..10)?;
    let mut parts = date.split('-');
    let (y, m, d): (i64, i64, i64) = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    // Days from civil, by Howard Hinnant's algorithm.
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let now = time::OffsetDateTime::now_utc().unix_timestamp() / 86_400;
    Some(now - days)
}

fn text(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap_or("").to_string()
}

impl ApiClient {
    pub fn new(
        base: &str,
        database: &str,
        login: &str,
        key: &str,
        major: Option<u32>,
    ) -> Result<ApiClient, String> {
        let (https, host, _) = super::external::split_url(base);
        if !https && !super::external::is_loopback(&host) {
            return Err(
                "refusing to send an API key over plain HTTP. Use an https:// address".to_string(),
            );
        }
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(40)))
            .http_status_as_error(false)
            .max_redirects(0)
            .user_agent(concat!("odoo-doctor/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        let mut client = ApiClient {
            agent,
            base: base.trim_end_matches('/').to_string(),
            database: database.to_string(),
            login: login.to_string(),
            key: key.to_string(),
            json2: major.is_some_and(|m| m >= 19),
            uid: None,
        };
        if !client.json2 {
            client.authenticate()?;
        }
        Ok(client)
    }

    fn post(&self, url: &str, body: &Value, bearer: bool) -> Result<(u16, String), String> {
        let mut request = self
            .agent
            .post(url)
            .header("Content-Type", "application/json");
        if bearer {
            request = request
                .header("Authorization", &format!("bearer {}", self.key))
                .header("X-Odoo-Database", &self.database);
        }
        let mut response = request.send(body.to_string()).map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .with_config()
            .limit(60_000_000)
            .read_to_string()
            .map_err(|e| e.to_string())?;
        Ok((status, text))
    }

    fn authenticate(&mut self) -> Result<(), String> {
        let body = json!({"jsonrpc": "2.0", "method": "call", "id": 1, "params": {
            "service": "common", "method": "authenticate", "args": [self.database, self.login, self.key, {}]
        }});
        let (status, text) = self.post(&format!("{}/jsonrpc", self.base), &body, false)?;
        let parsed: Value = serde_json::from_str(&text)
            .map_err(|_| format!("the API answered with HTTP {status}"))?;
        match parsed["result"].as_i64() {
            Some(uid) => {
                self.uid = Some(uid);
                Ok(())
            }
            None => Err("login failed: check the database, login and API key".to_string()),
        }
    }

    pub fn call(
        &self,
        model: &str,
        method: &str,
        domain: Value,
        fields: &[&str],
        limit: u64,
    ) -> Result<Value, String> {
        if !ALLOWED_METHODS.contains(&method) {
            return Err(format!("method {method} is not allowed"));
        }
        if self.json2 {
            let mut body = json!({"context": {"active_test": false}});
            match method {
                "fields_get" => {}
                "search_count" => body["domain"] = domain,
                _ => {
                    body["domain"] = domain;
                    body["fields"] = json!(fields);
                    body["limit"] = json!(limit);
                }
            }
            let url = format!("{}/json/2/{model}/{method}", self.base);
            let (status, text) = self.post(&url, &body, true)?;
            let parsed: Value = serde_json::from_str(&text)
                .map_err(|_| format!("HTTP {status} from {model}.{method}"))?;
            if status != 200 {
                let message = parsed["message"].as_str().unwrap_or("request refused");
                return Err(format!(
                    "{model}.{method}: HTTP {status}: {}",
                    message.chars().take(150).collect::<String>()
                ));
            }
            Ok(parsed)
        } else {
            let (args, kwargs) = match method {
                "fields_get" => (json!([]), json!({"context": {"active_test": false}})),
                "search_count" => (json!([domain]), json!({"context": {"active_test": false}})),
                _ => (
                    json!([domain]),
                    json!({"fields": fields, "limit": limit, "context": {"active_test": false}}),
                ),
            };
            let body = json!({"jsonrpc": "2.0", "method": "call", "id": 1, "params": {
                "service": "object", "method": "execute_kw",
                "args": [self.database, self.uid, self.key, model, method, args, kwargs]
            }});
            let (status, text) = self.post(&format!("{}/jsonrpc", self.base), &body, false)?;
            let parsed: Value = serde_json::from_str(&text)
                .map_err(|_| format!("HTTP {status} from {model}.{method}"))?;
            if let Some(error) = parsed.get("error") {
                let message = error["data"]["message"]
                    .as_str()
                    .or(error["message"].as_str())
                    .unwrap_or("request refused");
                return Err(format!(
                    "{model}.{method}: {}",
                    message.chars().take(150).collect::<String>()
                ));
            }
            Ok(parsed["result"].clone())
        }
    }

    fn rows(
        &self,
        model: &str,
        domain: Value,
        fields: &[&str],
        limit: u64,
    ) -> Result<Vec<Value>, String> {
        match self.call(model, "search_read", domain, fields, limit)? {
            Value::Array(rows) => Ok(rows),
            _ => Err(format!("{model}: unexpected answer")),
        }
    }

    fn count(&self, model: &str, domain: Value) -> Result<i64, String> {
        self.call(model, "search_count", domain, &[], 0)?
            .as_i64()
            .ok_or_else(|| format!("{model}: unexpected answer"))
    }

    fn known_fields(
        &self,
        model: &str,
        wanted: &[&'static str],
    ) -> Result<Vec<&'static str>, String> {
        let all = self.call(model, "fields_get", json!([]), &[], 0)?;
        Ok(wanted
            .iter()
            .copied()
            .filter(|f| all.get(*f).is_some())
            .collect())
    }
}

pub fn collect(api: &ApiClient) -> Result<OdooData, String> {
    let mut data = OdooData {
        source: "Odoo external API".to_string(),
        ..OdooData::default()
    };
    let mut gaps = Vec::new();
    // The first call proves that the credentials work, so its failure stops this layer.
    let modules = api.rows(
        "ir.module.module",
        json!([["state", "not in", ["uninstalled", "uninstallable"]]]),
        &["name", "state", "latest_version", "author", "demo"],
        5000,
    )?;
    data.modules = modules
        .iter()
        .map(|r| Module {
            name: text(r, "name"),
            state: text(r, "state"),
            version: text(r, "latest_version"),
            author: text(r, "author"),
            demo: r["demo"].as_bool().unwrap_or(false),
        })
        .collect();
    if let Some(base) = data.modules.iter().find(|m| m.name == "base") {
        data.major = major_of(&base.version);
        data.version = Some(base.version.clone());
    }
    if let Err(e) = read_users(api, &mut data) {
        gaps.push(format!("users: {e}"));
    }
    if let Err(e) = read_crons(api, &mut data) {
        gaps.push(format!("scheduled actions: {e}"));
    }
    if let Err(e) = read_mail(api, &mut data) {
        gaps.push(format!("mail: {e}"));
    }
    match api.rows(
        "ir.config_parameter",
        json!([["key", "in", SAFE_PARAMS]]),
        &["key", "value"],
        50,
    ) {
        Ok(rows) => {
            for r in rows {
                data.params.insert(text(&r, "key"), text(&r, "value"));
            }
        }
        Err(e) => gaps.push(format!("system parameters: {e}")),
    }
    gaps.push("model access rules are only checked with database access".to_string());
    data.gaps = gaps;
    Ok(data)
}

fn read_users(api: &ApiClient, data: &mut OdooData) -> Result<(), String> {
    let groups = api.rows(
        "ir.model.data",
        json!([
            ["module", "=", "base"],
            ["name", "=", "group_system"],
            ["model", "=", "res.groups"]
        ]),
        &["res_id"],
        1,
    )?;
    let admin_group = groups.first().and_then(|g| g["res_id"].as_i64());
    let fields = api.known_fields(
        "res.users",
        &[
            "login",
            "active",
            "share",
            "login_date",
            "totp_enabled",
            "group_ids",
            "groups_id",
        ],
    )?;
    let group_field = if fields.contains(&"group_ids") {
        "group_ids"
    } else {
        "groups_id"
    };
    let rows = api.rows("res.users", json!([]), &fields, 20_000)?;
    data.users = rows
        .iter()
        .map(|r| User {
            id: r["id"].as_i64().unwrap_or(0),
            login: text(r, "login"),
            active: r["active"].as_bool().unwrap_or(false),
            share: r["share"].as_bool().unwrap_or(false),
            is_admin: admin_group.is_some_and(|g| {
                r[group_field]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|v| v.as_i64() == Some(g)))
            }),
            days_since_login: r["login_date"].as_str().and_then(days_since),
            has_totp: r["totp_enabled"].as_bool(),
            plaintext_password: None,
            api_keys: None,
        })
        .collect();
    Ok(())
}

fn read_crons(api: &ApiClient, data: &mut OdooData) -> Result<(), String> {
    let fields = api.known_fields(
        "ir.cron",
        &[
            "cron_name",
            "active",
            "nextcall",
            "interval_number",
            "interval_type",
            "failure_count",
        ],
    )?;
    let rows = api.rows("ir.cron", json!([]), &fields, 2000)?;
    data.crons = rows
        .iter()
        .map(|r| Cron {
            name: text(r, "cron_name"),
            active: r["active"].as_bool().unwrap_or(false),
            days_overdue: r["nextcall"].as_str().and_then(days_since).unwrap_or(0) as f64,
            interval: format!(
                "{} {}",
                r["interval_number"],
                r["interval_type"].as_str().unwrap_or("")
            ),
            failure_count: r["failure_count"].as_i64(),
        })
        .collect();
    Ok(())
}

fn read_mail(api: &ApiClient, data: &mut OdooData) -> Result<(), String> {
    let rows = api.rows(
        "ir.mail_server",
        json!([["active", "=", true]]),
        &["name", "smtp_encryption"],
        100,
    )?;
    data.mail_servers = rows
        .iter()
        .map(|r| MailServer {
            name: text(r, "name"),
            encryption: text(r, "smtp_encryption"),
        })
        .collect();
    let since = time::OffsetDateTime::now_utc() - time::Duration::days(30);
    let cutoff = format!(
        "{:04}-{:02}-{:02} 00:00:00",
        since.year(),
        u8::from(since.month()),
        since.day()
    );
    let failed = api.count(
        "mail.mail",
        json!([["state", "=", "exception"], ["create_date", ">", cutoff]]),
    )?;
    data.mail = MailStats {
        failed_30d: failed,
        stuck_outgoing: 0,
        oldest_stuck_hours: 0.0,
        available: true,
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_plain_http_for_remote_hosts() {
        let err = ApiClient::new("http://erp.example.com", "db", "u", "k", Some(19))
            .err()
            .unwrap();
        assert!(err.contains("plain HTTP"));
    }

    #[test]
    fn write_methods_are_refused_before_any_network_call() {
        let client = ApiClient::new("http://127.0.0.1:9", "db", "u", "k", Some(19)).unwrap();
        for method in ["write", "create", "unlink", "action_archive", "execute"] {
            assert!(client
                .call("res.users", method, json!([]), &[], 0)
                .unwrap_err()
                .contains("not allowed"));
        }
    }

    #[test]
    fn date_arithmetic_handles_year_boundaries() {
        let today = time::OffsetDateTime::now_utc().date();
        let stamp = format!(
            "{:04}-{:02}-{:02} 10:00:00",
            today.year(),
            u8::from(today.month()),
            today.day()
        );
        assert_eq!(days_since(&stamp), Some(0));
        assert!(days_since("2000-02-29 00:00:00").unwrap() > 9000);
        assert_eq!(days_since("garbage"), None);
    }
}
