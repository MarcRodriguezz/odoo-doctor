//! What anyone on the network can see. Unauthenticated GETs and version calls, a TLS handshake,
//! and TCP connects to two ports. It never tries to log in or to guess passwords.
use crate::tls::{self, CertInfo};
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct ExternalData {
    pub base_url: String,
    pub host: String,
    pub https: bool,
    /// Local addresses: exposure findings would be meaningless, so they are skipped.
    pub loopback: bool,
    pub reachable: bool,
    pub server_version: Option<String>,
    pub server_serie: Option<String>,
    pub db_manager_open: bool,
    pub db_list: Option<Vec<String>>,
    pub signup_open: bool,
    pub http_redirects_to_https: Option<bool>,
    pub hsts: bool,
    pub cookie_secure: Option<bool>,
    pub certificate: Option<CertInfo>,
    pub tls_error: Option<String>,
    pub open_ports: Vec<u16>,
    pub error: Option<String>,
}

fn agent(verify: bool) -> ureq::Agent {
    let mut builder = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(12)))
        .http_status_as_error(false)
        .max_redirects(0)
        .user_agent(concat!("odoo-doctor/", env!("CARGO_PKG_VERSION")));
    if !verify {
        builder = builder.tls_config(
            ureq::tls::TlsConfig::builder()
                .disable_verification(true)
                .build(),
        );
    }
    builder.build().into()
}

struct Page {
    status: u16,
    location: Option<String>,
    hsts: bool,
    cookies: Vec<String>,
    body: String,
}

fn get(agent: &ureq::Agent, url: &str) -> Result<Page, String> {
    let mut resp = agent.get(url).call().map_err(|e| e.to_string())?;
    page(&mut resp)
}

fn page(resp: &mut ureq::http::Response<ureq::Body>) -> Result<Page, String> {
    let status = resp.status().as_u16();
    let headers = resp.headers();
    let location = headers
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let hsts = headers.contains_key("strict-transport-security");
    let cookies = headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect();
    let body = resp
        .body_mut()
        .with_config()
        .limit(2_000_000)
        .read_to_string()
        .unwrap_or_default();
    Ok(Page {
        status,
        location,
        hsts,
        cookies,
        body,
    })
}

fn rpc(agent: &ureq::Agent, url: &str) -> Option<Value> {
    let body = json!({"jsonrpc": "2.0", "method": "call", "params": {}, "id": 1}).to_string();
    let mut resp = agent
        .post(url)
        .header("Content-Type", "application/json")
        .send(body)
        .ok()?;
    if resp.status().as_u16() != 200 {
        return None;
    }
    let text = resp
        .body_mut()
        .with_config()
        .limit(1_000_000)
        .read_to_string()
        .ok()?;
    let parsed: Value = serde_json::from_str(&text).ok()?;
    parsed.get("result").cloned()
}

pub fn split_url(url: &str) -> (bool, String, Option<u16>) {
    let https = url.starts_with("https://");
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split('/').next().unwrap_or(rest);
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if let Some(stripped) = authority.strip_prefix('[') {
        // IPv6 literal.
        let (host, port) = stripped.split_once(']').unwrap_or((stripped, ""));
        return (
            https,
            host.to_string(),
            port.trim_start_matches(':').parse().ok(),
        );
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => {
            (https, host.to_string(), port.parse().ok())
        }
        _ => (https, authority.to_string(), None),
    }
}

pub fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host == "::1"
        || host.starts_with("127.")
        || host == "host.docker.internal"
}

fn is_private(host: &str) -> bool {
    let Ok(ip) = host.parse::<std::net::IpAddr>() else {
        return false;
    };
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        std::net::IpAddr::V6(v6) => v6.is_loopback(),
    }
}

fn port_open(host: &str, port: u16) -> bool {
    tls::connect(host, port, Duration::from_secs(3)).is_ok()
}

pub fn normalize_url(input: &str) -> String {
    let trimmed = input.trim().trim_end_matches('/');
    if trimmed.contains("://") {
        trimmed.to_string()
    } else if is_loopback(trimmed.split(':').next().unwrap_or("")) {
        format!("http://{trimmed}")
    } else {
        format!("https://{trimmed}")
    }
}

pub fn collect(url: &str, treat_as_public: bool, probe_ports: bool) -> ExternalData {
    tls::install_crypto();
    let base = normalize_url(url);
    let (https, host, port) = split_url(&base);
    let mut data = ExternalData {
        base_url: base.clone(),
        host: host.clone(),
        https,
        loopback: !treat_as_public && (is_loopback(&host) || is_private(&host)),
        ..ExternalData::default()
    };
    let mut client = agent(true);
    if https {
        match tls::peer_certificate(&host, port.unwrap_or(443)) {
            Ok(cert) => data.certificate = Some(cert),
            Err(e) => data.tls_error = Some(e),
        }
    }
    let login = format!("{base}/web/login");
    let page_login = match get(&client, &login) {
        Ok(p) => Some(p),
        Err(e) if https => {
            // Keep looking if the certificate is the only problem. Nothing sensitive is sent here.
            data.tls_error = Some(e);
            client = agent(false);
            get(&client, &login).ok()
        }
        Err(e) => {
            data.error = Some(e);
            None
        }
    };
    let Some(page_login) = page_login else {
        if data.error.is_none() {
            data.error = data.tls_error.clone();
        }
        return data;
    };
    data.reachable = true;
    data.hsts = page_login.hsts;
    data.cookie_secure = page_login
        .cookies
        .iter()
        .find(|c| c.starts_with("session_id="))
        .map(|c| {
            c.to_ascii_lowercase()
                .split(';')
                .any(|part| part.trim() == "secure")
        });

    if let Some(info) = rpc(&client, &format!("{base}/web/webclient/version_info")) {
        data.server_version = info["server_version"].as_str().map(str::to_string);
        data.server_serie = info["server_serie"].as_str().map(str::to_string);
    }
    if let Ok(p) = get(&client, &format!("{base}/web/database/manager")) {
        data.db_manager_open =
            p.status == 200 && (p.body.contains("database") || p.body.contains("Database"));
    }
    if let Some(Value::Array(list)) = rpc(&client, &format!("{base}/web/database/list")) {
        data.db_list = Some(
            list.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
        );
    }
    if let Ok(p) = get(&client, &format!("{base}/web/signup")) {
        // Odoo redirects to the login page when signup is closed.
        data.signup_open = p.status == 200
            && (p.body.contains("confirm_password") || p.body.contains("oe_signup_form"));
    }
    if https && !data.loopback {
        let plain = format!("http://{host}/web/login");
        if let Ok(p) = get(&client, &plain) {
            data.http_redirects_to_https = Some(
                (300..400).contains(&p.status)
                    && p.location
                        .as_deref()
                        .is_some_and(|l| l.starts_with("https://")),
            );
        }
    }
    if probe_ports && !data.loopback {
        for port in [8069u16, 5432] {
            let is_target_port = port == split_url(&base).2.unwrap_or(0);
            if !is_target_port && port_open(&host, port) {
                data.open_ports.push(port);
            }
        }
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_urls() {
        assert_eq!(split_url("https://a.com/x"), (true, "a.com".into(), None));
        assert_eq!(
            split_url("http://a.com:8069"),
            (false, "a.com".into(), Some(8069))
        );
        assert_eq!(
            split_url("http://[::1]:8069/x"),
            (false, "::1".into(), Some(8069))
        );
    }

    #[test]
    fn port_checks_try_every_address_of_a_host() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(port_open("localhost", port));
        drop(listener);
        assert!(!port_open("localhost", port));
    }

    #[test]
    fn adds_a_sensible_scheme() {
        assert_eq!(normalize_url("erp.example.com/"), "https://erp.example.com");
        assert_eq!(normalize_url("localhost:8069"), "http://localhost:8069");
        assert_eq!(normalize_url("http://x.io"), "http://x.io");
    }

    #[test]
    fn local_addresses_are_not_treated_as_exposed() {
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("localhost"));
        assert!(!is_loopback("example.com"));
        assert!(is_private("192.168.1.10"));
        assert!(!is_private("8.8.8.8"));
        assert!(!is_private("example.com"));
    }
}
