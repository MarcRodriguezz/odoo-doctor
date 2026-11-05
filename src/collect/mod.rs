//! Collectors gather facts. They make no judgments: that is the job of `checks`.
pub mod api;
pub mod conf;
pub mod external;
pub mod logs;
pub mod odoo;
pub mod pg;
pub mod sql;

use crate::code::CodeData;

#[derive(Debug, Clone, Default)]
pub struct HostData {
    pub disk_used_pct: Option<u32>,
    pub disk_path: String,
}

/// Everything known about the target. Checks are pure functions of this struct.
#[derive(Debug)]
pub struct Snapshot {
    pub deployment: String,
    pub database: Option<String>,
    pub external: Option<external::ExternalData>,
    pub conf: Option<conf::OdooConf>,
    pub odoo: Option<odoo::OdooData>,
    pub pg: Option<pg::PgData>,
    pub code: Option<CodeData>,
    pub logs: Option<logs::LogData>,
    pub host: Option<HostData>,
    pub db_count: Option<usize>,
    /// Requested target for upgrade checks. Defaults to the next major version.
    pub target_major: Option<u32>,
    /// Reasons a layer did not run, shown in the coverage section.
    pub skipped: Vec<(crate::model::Layer, String)>,
    /// Odoo operates the server (Odoo.sh, Odoo Online), so its settings are not the user's to change.
    pub managed: bool,
    /// False when `--pg` connected with a role that may not be the one Odoo uses.
    pub pg_role_is_odoos: bool,
}

impl Default for Snapshot {
    fn default() -> Self {
        Snapshot {
            deployment: String::new(),
            database: None,
            external: None,
            conf: None,
            odoo: None,
            pg: None,
            code: None,
            logs: None,
            host: None,
            db_count: None,
            target_major: None,
            skipped: Vec::new(),
            managed: false,
            pg_role_is_odoos: true,
        }
    }
}

impl Snapshot {
    pub fn major(&self) -> Option<u32> {
        self.odoo.as_ref().and_then(|o| o.major).or_else(|| {
            self.external
                .as_ref()
                .and_then(|e| e.server_serie.as_deref())
                .and_then(odoo::major_of)
        })
    }

    pub fn version_label(&self) -> Option<String> {
        self.external
            .as_ref()
            .and_then(|e| e.server_version.clone())
            .or_else(|| self.odoo.as_ref().and_then(|o| o.version.clone()))
    }
}
