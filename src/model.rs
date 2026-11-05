//! Core types shared by collectors, checks and reports.
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }

    pub fn parse(value: &str) -> Option<Severity> {
        match value.to_ascii_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            "info" => Some(Severity::Info),
            _ => None,
        }
    }

    fn penalty(self) -> f64 {
        match self {
            Severity::Critical => 22.0,
            Severity::High => 8.0,
            Severity::Medium => 3.0,
            Severity::Low => 1.0,
            Severity::Info => 0.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Observed directly. A false positive means the tool has a bug.
    Certain,
    /// Inferred from a pattern. A person should confirm it.
    Probable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Security,
    Reliability,
    Performance,
    Upgrade,
    Quality,
}

impl Category {
    pub const ALL: [Category; 5] = [
        Category::Security,
        Category::Reliability,
        Category::Performance,
        Category::Upgrade,
        Category::Quality,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Category::Security => "Security",
            Category::Reliability => "Reliability",
            Category::Performance => "Performance",
            Category::Upgrade => "Upgrade",
            Category::Quality => "Code quality",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    External,
    Config,
    Database,
    Postgres,
    Code,
    Logs,
    Host,
}

impl Layer {
    pub const ALL: [Layer; 7] = [
        Layer::External,
        Layer::Config,
        Layer::Database,
        Layer::Postgres,
        Layer::Code,
        Layer::Logs,
        Layer::Host,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Layer::External => "External exposure",
            Layer::Config => "Odoo configuration",
            Layer::Database => "Odoo data (users, crons, mail, modules)",
            Layer::Postgres => "PostgreSQL health",
            Layer::Code => "Custom module code",
            Layer::Logs => "Server logs",
            Layer::Host => "Host",
        }
    }
}

/// Static description of a check. Findings copy their text from here.
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub category: Category,
    pub layer: Layer,
    pub why: &'static str,
    pub fix: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Location {
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub category: Category,
    pub layer: Layer,
    pub summary: String,
    pub evidence: Vec<String>,
    pub locations: Vec<Location>,
    pub why: String,
    pub fix: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LayerState {
    Ran,
    Partial,
    Skipped,
}

/// What was examined and, just as important, what was not.
#[derive(Debug, Clone, Serialize)]
pub struct LayerStatus {
    pub layer: Layer,
    pub label: String,
    pub state: LayerState,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Counts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CategoryScore {
    pub category: Category,
    pub label: String,
    pub score: u32,
    pub findings: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub tool_version: String,
    pub generated_at: String,
    pub target: String,
    pub deployment: String,
    pub odoo_version: Option<String>,
    pub database: Option<String>,
    pub upgrade_target: Option<u32>,
    pub score: u32,
    pub grade: String,
    /// Set when too little was examined for a grade to mean anything.
    pub limited: Option<String>,
    pub counts: Counts,
    pub categories: Vec<CategoryScore>,
    pub layers: Vec<LayerStatus>,
    pub facts: Vec<(String, String)>,
    pub findings: Vec<Finding>,
    pub redacted: bool,
}

fn category_score(findings: &[Finding], category: Option<Category>) -> u32 {
    let total: f64 = findings
        .iter()
        .filter(|f| category.is_none_or(|c| f.category == c))
        .map(|f| {
            let weight = if f.confidence == Confidence::Probable {
                0.6
            } else {
                1.0
            };
            f.severity.penalty() * weight
        })
        .sum();
    // Exponential decay: the score never goes negative and early problems cost the most.
    (100.0 * (-total / 100.0).exp()).round() as u32
}

pub fn score(findings: &[Finding]) -> u32 {
    category_score(findings, None)
}

pub fn grade(score: u32, findings: &[Finding]) -> &'static str {
    let critical = findings.iter().any(|f| f.severity == Severity::Critical);
    match score {
        _ if critical && score >= 60 => "D",
        90..=100 => "A",
        75..=89 => "B",
        60..=74 => "C",
        40..=59 => "D",
        _ => "F",
    }
}

pub fn category_scores(findings: &[Finding]) -> Vec<CategoryScore> {
    Category::ALL
        .iter()
        .map(|c| CategoryScore {
            category: *c,
            label: c.label().to_string(),
            score: category_score(findings, Some(*c)),
            findings: findings.iter().filter(|f| f.category == *c).count(),
        })
        .collect()
}

pub fn count(findings: &[Finding]) -> Counts {
    let mut counts = Counts::default();
    for finding in findings {
        match finding.severity {
            Severity::Critical => counts.critical += 1,
            Severity::High => counts.high += 1,
            Severity::Medium => counts.medium += 1,
            Severity::Low => counts.low += 1,
            Severity::Info => counts.info += 1,
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: Severity, confidence: Confidence, category: Category) -> Finding {
        Finding {
            id: "X".into(),
            title: "x".into(),
            severity,
            confidence,
            category,
            layer: Layer::Config,
            summary: String::new(),
            evidence: vec![],
            locations: vec![],
            why: String::new(),
            fix: String::new(),
        }
    }

    #[test]
    fn clean_system_scores_100_and_a() {
        assert_eq!(score(&[]), 100);
        assert_eq!(grade(100, &[]), "A");
    }

    #[test]
    fn info_does_not_lower_the_score() {
        let f = [finding(
            Severity::Info,
            Confidence::Certain,
            Category::Quality,
        )];
        assert_eq!(score(&f), 100);
    }

    #[test]
    fn a_critical_caps_the_grade_at_d() {
        let f = [finding(
            Severity::Critical,
            Confidence::Certain,
            Category::Security,
        )];
        assert!(score(&f) >= 60);
        assert_eq!(grade(score(&f), &f), "D");
    }

    #[test]
    fn probable_findings_cost_less_than_certain_ones() {
        let certain = [finding(
            Severity::High,
            Confidence::Certain,
            Category::Security,
        )];
        let probable = [finding(
            Severity::High,
            Confidence::Probable,
            Category::Security,
        )];
        assert!(score(&probable) > score(&certain));
    }

    #[test]
    fn score_stays_in_range_however_many_findings() {
        let many: Vec<_> = (0..500)
            .map(|_| finding(Severity::Critical, Confidence::Certain, Category::Security))
            .collect();
        assert!(score(&many) <= 100);
        assert_eq!(grade(score(&many), &many), "F");
    }

    #[test]
    fn category_score_ignores_other_categories() {
        let f = [finding(
            Severity::Critical,
            Confidence::Certain,
            Category::Security,
        )];
        let scores = category_scores(&f);
        let perf = scores
            .iter()
            .find(|s| s.category == Category::Performance)
            .unwrap();
        assert_eq!(perf.score, 100);
    }
}
