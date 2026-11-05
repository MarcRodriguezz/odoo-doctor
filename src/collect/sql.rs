//! Read-only SQL access, either directly or through `psql` in a container or over SSH.
//!
//! Every statement runs in a session set to `default_transaction_read_only = on`, so PostgreSQL
//! itself refuses writes. Both paths wrap queries in `json_agg`, so callers get the same JSON.
use crate::tls;
use crate::transport::{first_line, Transport};
use serde_json::Value;

const SESSION: &str = "SET default_transaction_read_only = on; SET statement_timeout = '30s'; SET lock_timeout = '2s'; SET application_name = 'odoo-doctor';";

pub enum SqlClient {
    Direct {
        client: Box<postgres::Client>,
        params: DirectParams,
    },
    Psql {
        transport: Transport,
        args: Vec<String>,
        password: Option<String>,
        database: String,
    },
}

#[derive(Debug, Clone, Default)]
pub struct DirectParams {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub sslmode: Option<String>,
    pub database: String,
}

fn wrap(query: &str) -> String {
    format!(
        "SELECT coalesce(json_agg(t), '[]')::text FROM ({}) t",
        query.trim().trim_end_matches(';')
    )
}

fn connect_direct(params: &DirectParams) -> Result<postgres::Client, String> {
    let mut config = postgres::Config::new();
    config.application_name("odoo-doctor");
    config.connect_timeout(std::time::Duration::from_secs(8));
    config.dbname(&params.database);
    if let Some(host) = &params.host {
        config.host(host);
    } else if cfg!(unix) {
        // Same default as libpq: the local socket.
        let socket = ["/var/run/postgresql", "/tmp"]
            .into_iter()
            .find(|d| std::path::Path::new(d).exists())
            .unwrap_or("/var/run/postgresql");
        config.host(socket);
    } else {
        config.host("localhost");
    }
    if let Some(port) = params.port {
        config.port(port);
    }
    let os_user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "odoo".into());
    config.user(params.user.as_deref().unwrap_or(&os_user));
    if let Some(password) = &params.password {
        config.password(password);
    }
    let mode = params.sslmode.as_deref().unwrap_or("prefer");
    let (ssl, tls_config) = match mode {
        "disable" => (postgres::config::SslMode::Disable, tls::unverified_config()),
        "require" => (postgres::config::SslMode::Require, tls::unverified_config()),
        "verify-ca" | "verify-full" => (postgres::config::SslMode::Require, tls::verified_config()),
        _ => (postgres::config::SslMode::Prefer, tls::unverified_config()),
    };
    config.ssl_mode(ssl);
    let connector = tokio_postgres_rustls::MakeRustlsConnect::new(tls_config);
    config.connect(connector).map_err(|e| {
        let detail = std::error::Error::source(&e)
            .map(|s| s.to_string())
            .unwrap_or_else(|| e.to_string());
        first_line(&detail)
    })
}

impl SqlClient {
    pub fn direct(params: DirectParams) -> Result<SqlClient, String> {
        let mut client = connect_direct(&params)?;
        client.batch_execute(SESSION).map_err(|e| e.to_string())?;
        Ok(SqlClient::Direct {
            client: Box::new(client),
            params,
        })
    }

    /// Parses `postgres://user:pass@host:port/db?sslmode=x`.
    pub fn parse_url(url: &str) -> Result<DirectParams, String> {
        let rest = url
            .strip_prefix("postgres://")
            .or_else(|| url.strip_prefix("postgresql://"))
            .ok_or("the Postgres URL must start with postgres://")?;
        let (main, query) = rest.split_once('?').unwrap_or((rest, ""));
        let (authority, database) = main.split_once('/').unwrap_or((main, ""));
        let (credentials, hostport) = match authority.rsplit_once('@') {
            Some((c, h)) => (Some(c), h),
            None => (None, authority),
        };
        let mut params = DirectParams {
            database: percent_decode(database),
            ..DirectParams::default()
        };
        if let Some(c) = credentials {
            let (user, password) = c.split_once(':').unwrap_or((c, ""));
            params.user = Some(percent_decode(user));
            if !password.is_empty() {
                params.password = Some(percent_decode(password));
            }
        }
        if !hostport.is_empty() {
            let (host, port) = match hostport.rsplit_once(':') {
                Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (h, p.parse().ok()),
                _ => (hostport, None),
            };
            params.host = Some(host.to_string());
            params.port = port;
        }
        for pair in query.split('&') {
            if let Some(("sslmode", value)) = pair.split_once('=') {
                params.sslmode = Some(value.to_string());
            }
        }
        Ok(params)
    }

    pub fn database(&self) -> &str {
        match self {
            SqlClient::Direct { params, .. } => &params.database,
            SqlClient::Psql { database, .. } => database,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            SqlClient::Direct { params, .. } => format!(
                "direct connection to {}",
                params.host.as_deref().unwrap_or("local socket")
            ),
            SqlClient::Psql { transport, .. } => format!("psql on {}", transport.describe()),
        }
    }

    /// Returns the same kind of client, pointed at another database.
    pub fn with_database(&self, database: &str) -> Result<SqlClient, String> {
        match self {
            SqlClient::Direct { params, .. } => {
                let mut next = params.clone();
                next.database = database.to_string();
                SqlClient::direct(next)
            }
            SqlClient::Psql {
                transport,
                args,
                password,
                ..
            } => Ok(SqlClient::Psql {
                transport: transport.clone(),
                args: args.clone(),
                password: password.clone(),
                database: database.to_string(),
            }),
        }
    }

    pub fn rows(&mut self, query: &str) -> Result<Vec<Value>, String> {
        let wrapped = wrap(query);
        let text = match self {
            SqlClient::Direct { client, .. } => {
                let rows = client.simple_query(&wrapped).map_err(|e| {
                    std::error::Error::source(&e)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| e.to_string())
                })?;
                rows.iter()
                    .find_map(|m| match m {
                        postgres::SimpleQueryMessage::Row(row) => row.get(0).map(str::to_string),
                        _ => None,
                    })
                    .unwrap_or_else(|| "[]".to_string())
            }
            SqlClient::Psql {
                transport,
                args,
                password,
                database,
            } => {
                let mut argv: Vec<&str> =
                    vec!["psql", "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1"];
                argv.extend(args.iter().map(String::as_str));
                if !database.is_empty() {
                    argv.push("-d");
                    argv.push(database);
                }
                let script = format!("{SESSION}\n{wrapped};\n");
                let envs: Vec<(&str, &str)> = password
                    .iter()
                    .map(|p| ("PGPASSWORD", p.as_str()))
                    .collect();
                let out = transport.run_with(&argv, Some(&script), &envs)?;
                if !out.success {
                    return Err(first_line(&out.stderr));
                }
                out.text()
            }
        };
        let trimmed = text.trim();
        match serde_json::from_str(trimmed) {
            Ok(Value::Array(rows)) => Ok(rows),
            _ => Err(format!(
                "unexpected database output: {}",
                first_line(trimmed)
            )),
        }
    }

    pub fn one(&mut self, query: &str) -> Result<Value, String> {
        Ok(self.rows(query)?.into_iter().next().unwrap_or(Value::Null))
    }

    /// Whether a relation exists, so version-dependent queries can skip cleanly.
    pub fn has_table(&mut self, table: &str) -> bool {
        let safe: String = table
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        self.one(&format!(
            "SELECT to_regclass('public.{safe}') IS NOT NULL AS present"
        ))
        .map(|v| v["present"].as_bool().unwrap_or(false))
        .unwrap_or(false)
    }

    pub fn has_column(&mut self, table: &str, column: &str) -> bool {
        let clean = |s: &str| {
            s.chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect::<String>()
        };
        self.one(&format!(
            "SELECT count(*) > 0 AS present FROM information_schema.columns WHERE table_schema = 'public' AND table_name = '{}' AND column_name = '{}'",
            clean(table),
            clean(column)
        ))
        .map(|v| v["present"].as_bool().unwrap_or(false))
        .unwrap_or(false)
    }
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let decoded = (bytes[i] == b'%')
            .then(|| bytes.get(i + 1..i + 3))
            .flatten()
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match decoded {
            Some(byte) => {
                out.push(byte);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_url() {
        let p =
            SqlClient::parse_url("postgres://odoo:p%40ss@db.example.com:5433/prod?sslmode=require")
                .unwrap();
        assert_eq!(p.user.as_deref(), Some("odoo"));
        assert_eq!(p.password.as_deref(), Some("p@ss"));
        assert_eq!(p.host.as_deref(), Some("db.example.com"));
        assert_eq!(p.port, Some(5433));
        assert_eq!(p.database, "prod");
        assert_eq!(p.sslmode.as_deref(), Some("require"));
    }

    #[test]
    fn parses_a_minimal_url_and_rejects_others() {
        let p = SqlClient::parse_url("postgresql://localhost/odoo").unwrap();
        assert_eq!(p.host.as_deref(), Some("localhost"));
        assert_eq!(p.port, None);
        assert_eq!(p.user, None);
        assert!(SqlClient::parse_url("mysql://x/y").is_err());
    }

    #[test]
    fn wrapping_strips_the_trailing_semicolon() {
        assert_eq!(
            wrap("select 1;"),
            "SELECT coalesce(json_agg(t), '[]')::text FROM (select 1) t"
        );
    }

    #[test]
    fn percent_decoding_handles_edges() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }
}
