//! Command-line interface. Running with no arguments should do the right thing on any machine.
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "odoo-doctor",
    version,
    about = "Read-only health, security and upgrade audit for any Odoo deployment",
    long_about = "Audits an Odoo server without changing anything.\n\n\
Run it with no arguments on a machine with Odoo (native or Docker) and it finds everything by itself. \
Give it an address to audit a remote site from outside.",
    args_conflicts_with_subcommands = true,
    after_help = "EXAMPLES:\n  \
odoo-doctor                                  Find Odoo on this machine and audit it\n  \
odoo-doctor https://erp.example.com          Audit from outside, with no credentials\n  \
odoo-doctor --ssh user@server                Audit a server over SSH (native or Docker)\n  \
odoo-doctor --docker my-odoo                 Audit a specific container\n  \
odoo-doctor --ssh 12345@proj.odoo.com        Audit an Odoo.sh branch\n  \
odoo-doctor https://x.odoo.com --db x --login me@x.com --api-key KEY\n                                               Audit through the API (Odoo Online)\n  \
odoo-doctor --addons ./my-addons --target-version 20\n                                               Check code only, for an upgrade or in CI"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Address of the Odoo site. Without it, odoo-doctor looks on this machine.
    pub url: Option<String>,

    /// Audit a container. Without a name, it finds the Odoo container
    #[arg(long, value_name = "CONTAINER", num_args = 0..=1, default_missing_value = "", help_heading = "Where Odoo runs")]
    pub docker: Option<String>,

    /// Audit a server over SSH, using your SSH keys and config
    #[arg(long, value_name = "USER@HOST", help_heading = "Where Odoo runs")]
    pub ssh: Option<String>,

    /// Path to odoo.conf on the target
    #[arg(long, value_name = "FILE", help_heading = "Where Odoo runs")]
    pub conf: Option<String>,

    /// Audit this database, when the server has several
    #[arg(long, value_name = "NAME", help_heading = "Access")]
    pub db: Option<String>,

    /// Connect to PostgreSQL with this URL: postgres://user:pass@host:5432/db?sslmode=require
    #[arg(
        long,
        value_name = "URL",
        env = "ODOO_DOCTOR_PG",
        hide_env_values = true,
        help_heading = "Access"
    )]
    pub pg: Option<String>,

    /// API key for sites with no database access, such as Odoo Online
    #[arg(
        long,
        value_name = "KEY",
        env = "ODOO_API_KEY",
        hide_env_values = true,
        help_heading = "Access"
    )]
    pub api_key: Option<String>,

    /// Login that owns the API key
    #[arg(
        long,
        value_name = "LOGIN",
        env = "ODOO_LOGIN",
        help_heading = "Access"
    )]
    pub login: Option<String>,

    /// Directory of custom modules. Can be repeated. Without a server, this checks code only
    #[arg(long, value_name = "DIR", help_heading = "What to check")]
    pub addons: Vec<String>,

    /// Odoo version for the upgrade checks. Default: the next major version
    #[arg(long, value_name = "VERSION", help_heading = "What to check")]
    pub target_version: Option<u32>,

    /// Also analyze modules written by Odoo S.A.
    #[arg(long, help_heading = "What to check")]
    pub include_vendor: bool,

    /// Do not test whether ports 8069 and 5432 are open on the target
    #[arg(long, help_heading = "What to check")]
    pub no_port_probe: bool,

    /// Apply exposure checks to a local or private address, as if it were public
    #[arg(long, help_heading = "What to check")]
    pub treat_as_public: bool,

    /// HTML report path
    #[arg(
        long,
        value_name = "FILE",
        default_value = "odoo-doctor-report.html",
        help_heading = "Output"
    )]
    pub html: PathBuf,

    /// Do not write the HTML report
    #[arg(long, help_heading = "Output")]
    pub no_html: bool,

    /// Also write a JSON report
    #[arg(long, value_name = "FILE", help_heading = "Output")]
    pub json: Option<PathBuf>,

    /// Also write a SARIF report for GitHub code scanning
    #[arg(long, value_name = "FILE", help_heading = "Output")]
    pub sarif: Option<PathBuf>,

    /// Exit with code 1 if a finding reaches this level: critical, high, medium, low
    #[arg(long, value_name = "LEVEL", help_heading = "Output")]
    pub fail_on: Option<String>,

    /// Mask logins and database names, for reports you share with others
    #[arg(long, help_heading = "Output")]
    pub redact: bool,

    /// Show every finding in full in the terminal
    #[arg(short, long, help_heading = "Output")]
    pub verbose: bool,

    /// Do not ask questions. Fail if something is missing
    #[arg(long, help_heading = "Output")]
    pub no_input: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// List every check
    Checks,
    /// Explain one check
    Explain {
        /// Check ID, such as PY001
        id: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn docker_works_with_and_without_a_name() {
        let with = Cli::try_parse_from(["odoo-doctor", "--docker", "x"]).unwrap();
        assert_eq!(with.docker.as_deref(), Some("x"));
        let without = Cli::try_parse_from(["odoo-doctor", "--docker"]).unwrap();
        assert_eq!(without.docker.as_deref(), Some(""));
    }

    #[test]
    fn no_arguments_is_a_valid_invocation() {
        let cli = Cli::try_parse_from(["odoo-doctor"]).unwrap();
        assert!(cli.url.is_none() && cli.command.is_none());
    }

    #[test]
    fn a_subcommand_does_not_read_as_an_address() {
        let cli = Cli::try_parse_from(["odoo-doctor", "explain", "PY001"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Explain { .. })));
    }
}
