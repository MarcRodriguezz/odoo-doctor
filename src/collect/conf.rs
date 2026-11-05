//! Parses odoo.conf. Secrets are classified, and their values are dropped straight away.
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct OdooConf {
    pub path: String,
    pub values: BTreeMap<String, String>,
    pub admin_passwd: PasswordKind,
    /// `db_password`, kept only in memory to connect. It never reaches a report.
    pub db_password: Option<String>,
    pub world_readable: Option<bool>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PasswordKind {
    #[default]
    Missing,
    /// Odoo's documented default values and very short passwords.
    Weak,
    Plaintext,
    Hashed,
}

fn classify_master_password(value: &str) -> PasswordKind {
    let value = value.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("false") {
        return PasswordKind::Missing;
    }
    if value.starts_with("$pbkdf2") || value.starts_with("$argon2") || value.starts_with("$scrypt")
    {
        return PasswordKind::Hashed;
    }
    let lower = value.to_ascii_lowercase();
    if value.len() < 12
        || ["admin", "odoo", "password", "changeme", "123456"]
            .iter()
            .any(|w| lower.contains(w))
    {
        return PasswordKind::Weak;
    }
    PasswordKind::Plaintext
}

pub fn parse(path: &str, text: &str) -> OdooConf {
    let mut conf = OdooConf {
        path: path.to_string(),
        ..OdooConf::default()
    };
    let mut in_options = false;
    let mut seen_section = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            seen_section = true;
            in_options = line.eq_ignore_ascii_case("[options]");
            continue;
        }
        if seen_section && !in_options {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim().to_ascii_lowercase(), value.trim().to_string());
        match key.as_str() {
            "admin_passwd" => conf.admin_passwd = classify_master_password(&value),
            "db_password" => {
                if !value.is_empty() && !value.eq_ignore_ascii_case("false") {
                    conf.db_password = Some(value);
                }
            }
            // Other credentials are never needed, so they are not kept even in memory.
            k if k.contains("password")
                || k.contains("secret")
                || k.contains("smtp_pass")
                || k.contains("token") => {}
            _ => {
                conf.values.insert(key, value);
            }
        }
    }
    conf
}

impl OdooConf {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values
            .get(key)
            .map(String::as_str)
            .filter(|v| !v.is_empty() && !v.eq_ignore_ascii_case("false"))
    }

    pub fn flag(&self, key: &str) -> Option<bool> {
        let value = self.values.get(key)?.to_ascii_lowercase();
        Some(matches!(value.as_str(), "true" | "1" | "yes" | "on"))
    }

    pub fn int(&self, key: &str) -> Option<i64> {
        self.values.get(key)?.parse().ok()
    }

    pub fn addons_paths(&self) -> Vec<String> {
        self.values
            .get("addons_path")
            .map(|p| {
                p.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_master_passwords() {
        assert_eq!(classify_master_password(""), PasswordKind::Missing);
        assert_eq!(classify_master_password("False"), PasswordKind::Missing);
        assert_eq!(classify_master_password("admin"), PasswordKind::Weak);
        assert_eq!(
            classify_master_password("my-odoo-long-password"),
            PasswordKind::Weak
        );
        assert_eq!(classify_master_password("short1"), PasswordKind::Weak);
        assert_eq!(
            classify_master_password("Xk29fjQm3LpZv81n"),
            PasswordKind::Plaintext
        );
        assert_eq!(
            classify_master_password("$pbkdf2-sha512$600000$abc$def"),
            PasswordKind::Hashed
        );
    }

    #[test]
    fn parses_options_and_keeps_no_secret_text_in_values() {
        let conf = parse(
            "/x",
            "; comment\n[options]\nadmin_passwd = admin\ndb_password = s3cret\nsmtp_password = other\nworkers = 4\nlist_db=False\naddons_path = /a, /b\n[other]\nworkers = 9\n",
        );
        assert_eq!(conf.int("workers"), Some(4));
        assert_eq!(conf.flag("list_db"), Some(false));
        assert_eq!(conf.addons_paths(), vec!["/a", "/b"]);
        assert_eq!(conf.admin_passwd, PasswordKind::Weak);
        assert_eq!(conf.db_password.as_deref(), Some("s3cret"));
        assert!(conf
            .values
            .values()
            .all(|v| v != "admin" && v != "s3cret" && v != "other"));
    }

    #[test]
    fn get_treats_false_as_unset() {
        let conf = parse("/x", "[options]\ndb_host = False\ndb_name = lab\n");
        assert_eq!(conf.get("db_host"), None);
        assert_eq!(conf.get("db_name"), Some("lab"));
    }
}
