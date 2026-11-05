//! odoo-doctor: read-only health, security and upgrade audit for any Odoo deployment.
mod audit;
mod checks;
mod cli;
mod code;
mod collect;
mod model;
mod report;
mod tls;
mod transport;

use clap::Parser;
use cli::{Cli, Command};
use model::Severity;
use std::process::ExitCode;

const EXIT_OK: u8 = 0;
const EXIT_FINDINGS: u8 = 1;
const EXIT_ERROR: u8 = 2;

fn list_checks() {
    for rule in checks::catalog::RULES {
        anstream::println!(
            "{:<7} {:<9} {:<13} {}",
            rule.id,
            rule.severity.label(),
            rule.category.label(),
            rule.title
        );
    }
    anstream::println!(
        "\n{} checks. Use `odoo-doctor explain ID` for details.",
        checks::catalog::RULES.len()
    );
}

fn explain(id: &str) -> u8 {
    let wanted = id.to_ascii_uppercase();
    let Some(rule) = checks::catalog::RULES.iter().find(|r| r.id == wanted) else {
        eprintln!("Unknown check: {id}. Use `odoo-doctor checks` to list them.");
        return EXIT_ERROR;
    };
    anstream::println!("{}: {}\n", rule.id, rule.title);
    anstream::println!("Severity:   {}", rule.severity.label());
    anstream::println!("Category:   {}", rule.category.label());
    anstream::println!("Looks at:   {}", rule.layer.label());
    anstream::println!("\nWhy it matters\n  {}", rule.why);
    anstream::println!("\nHow to fix it\n  {}", rule.fix);
    EXIT_OK
}

fn write_outputs(cli: &Cli, report: &model::Report) -> Result<Vec<String>, String> {
    let mut written = Vec::new();
    if !cli.no_html {
        let page = report::html(report)?;
        std::fs::write(&cli.html, page).map_err(|e| format!("{}: {e}", cli.html.display()))?;
        written.push(cli.html.display().to_string());
    }
    if let Some(path) = &cli.json {
        let text = serde_json::to_string_pretty(report).map_err(|e| e.to_string())?;
        std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))?;
        written.push(path.display().to_string());
    }
    if let Some(path) = &cli.sarif {
        let text = serde_json::to_string_pretty(&report::sarif::render(report))
            .map_err(|e| e.to_string())?;
        std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))?;
        written.push(path.display().to_string());
    }
    Ok(written)
}

fn scan(cli: &Cli) -> u8 {
    let threshold = match cli.fail_on.as_deref().map(Severity::parse) {
        Some(None) => {
            eprintln!("--fail-on must be one of: critical, high, medium, low, info");
            return EXIT_ERROR;
        }
        Some(found) => found,
        None => None,
    };
    let snapshot = match audit::run(cli) {
        Ok(s) => s,
        Err(e) => {
            anstream::eprintln!("\x1b[31mError:\x1b[0m {e}");
            return EXIT_ERROR;
        }
    };
    let findings = checks::run(&snapshot);
    let report = report::build(&snapshot, findings, cli.redact);
    anstream::print!("{}", report::terminal::render(&report, cli.verbose));
    match write_outputs(cli, &report) {
        Ok(paths) => {
            for path in paths {
                anstream::println!("\nReport: \x1b[1m{path}\x1b[0m");
            }
        }
        Err(e) => {
            anstream::eprintln!("\x1b[31mCould not write the report:\x1b[0m {e}");
            return EXIT_ERROR;
        }
    }
    // Nothing was examined, so a passing exit code would be a lie.
    let examined = snapshot.external.as_ref().is_some_and(|e| e.reachable)
        || snapshot.conf.is_some()
        || snapshot.odoo.is_some()
        || snapshot.pg.is_some()
        || snapshot.code.is_some();
    if !examined {
        anstream::eprintln!(
            "\x1b[31mError:\x1b[0m nothing could be examined. See 'What was checked' above."
        );
        return EXIT_ERROR;
    }
    if threshold.is_some_and(|level| report.findings.iter().any(|f| f.severity <= level)) {
        return EXIT_FINDINGS;
    }
    EXIT_OK
}

fn main() -> ExitCode {
    // A parser panic on a strange file is handled per file, so its default message would be noise.
    std::panic::set_hook(Box::new(|_| {}));
    let cli = Cli::parse();
    let code = match &cli.command {
        Some(Command::Checks) => {
            list_checks();
            EXIT_OK
        }
        Some(Command::Explain { id }) => explain(id),
        None => scan(&cli),
    };
    ExitCode::from(code)
}
