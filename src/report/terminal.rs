//! Terminal output. `anstream` removes colors when piped and enables them on Windows consoles.
use crate::model::{LayerState, Report, Severity};
use std::fmt::Write;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";

fn severity_color(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "\x1b[1;97;41m",
        Severity::High => "\x1b[1;31m",
        Severity::Medium => "\x1b[33m",
        Severity::Low => "\x1b[36m",
        Severity::Info => "\x1b[2m",
    }
}

fn score_color(score: u32) -> &'static str {
    match score {
        75..=100 => "\x1b[1;32m",
        50..=74 => "\x1b[1;33m",
        _ => "\x1b[1;31m",
    }
}

fn bar(score: u32) -> String {
    let filled = (score as usize + 5) / 10;
    format!("{}{}", "█".repeat(filled), "░".repeat(10 - filled))
}

pub fn render(report: &Report, verbose: bool) -> String {
    let mut o = String::new();
    let _ = writeln!(
        o,
        "\n{BOLD}odoo-doctor{RESET} {DIM}{}{RESET}",
        report.tool_version
    );
    let _ = writeln!(o, "{DIM}{} · {}{RESET}", report.target, report.deployment);
    let mut identity = Vec::new();
    if let Some(v) = &report.odoo_version {
        identity.push(format!("Odoo {v}"));
    }
    if let Some(d) = &report.database {
        identity.push(format!("database {d}"));
    }
    if !identity.is_empty() {
        let _ = writeln!(o, "{DIM}{}{RESET}", identity.join(" · "));
    }
    let color = score_color(report.score);
    let _ = writeln!(
        o,
        "\n{color}{}/100  grade {}{RESET}",
        report.score, report.grade
    );
    let c = &report.counts;
    let _ = writeln!(
        o,
        "{} critical · {} high · {} medium · {} low · {} info\n",
        c.critical, c.high, c.medium, c.low, c.info
    );
    for category in &report.categories {
        let color = score_color(category.score);
        let _ = writeln!(
            o,
            "  {:<13} {color}{}{RESET} {:>3}",
            category.label,
            bar(category.score),
            category.score
        );
    }

    let _ = writeln!(o, "\n{BOLD}What was checked{RESET}");
    for layer in &report.layers {
        let (mark, color) = match layer.state {
            LayerState::Ran => ("✓", "\x1b[32m"),
            LayerState::Partial => ("~", "\x1b[33m"),
            LayerState::Skipped => ("–", "\x1b[2m"),
        };
        let _ = writeln!(
            o,
            "  {color}{mark}{RESET} {:<40} {DIM}{}{RESET}",
            layer.label, layer.detail
        );
    }

    if report.findings.is_empty() {
        let _ = writeln!(o, "\n\x1b[32mNo problems found in what was checked.{RESET}");
        return o;
    }
    let _ = writeln!(o, "\n{BOLD}Findings{RESET}");
    let limit = if verbose { usize::MAX } else { 4 };
    let mut hidden_info = 0;
    for f in &report.findings {
        if f.severity == Severity::Info && !verbose {
            hidden_info += 1;
            continue;
        }
        let color = severity_color(f.severity);
        let confidence = if f.confidence == crate::model::Confidence::Probable {
            " (probable)"
        } else {
            ""
        };
        let _ = writeln!(
            o,
            "\n{color} {} {RESET} {BOLD}{}{RESET} {DIM}{}{confidence}{RESET}",
            f.severity.label(),
            f.title,
            f.id
        );
        let _ = writeln!(o, "  {}", f.summary);
        for item in f.evidence.iter().take(limit) {
            let _ = writeln!(o, "  {DIM}· {item}{RESET}");
        }
        if f.evidence.len() > limit {
            let _ = writeln!(o, "  {DIM}· and {} more{RESET}", f.evidence.len() - limit);
        }
        for location in f.locations.iter().take(limit) {
            let _ = writeln!(o, "  {DIM}→ {}:{}{RESET}", location.file, location.line);
        }
        if f.locations.len() > limit {
            let _ = writeln!(o, "  {DIM}→ and {} more{RESET}", f.locations.len() - limit);
        }
        if verbose {
            let _ = writeln!(o, "  Why: {}", f.why);
        }
        let _ = writeln!(o, "  \x1b[32mFix:{RESET} {}", f.fix);
    }
    if hidden_info > 0 {
        let _ = writeln!(o, "\n{DIM}{hidden_info} informational note(s) not shown. Use --verbose to see them.{RESET}");
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bars_are_always_ten_wide() {
        for score in [0, 4, 5, 50, 95, 100] {
            assert_eq!(bar(score).chars().count(), 10, "{score}");
        }
    }
}
