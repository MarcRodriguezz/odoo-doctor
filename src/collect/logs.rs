//! Summarizes Odoo server logs into recurring error signatures.
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct LogData {
    pub source: String,
    pub lines: usize,
    pub errors: usize,
    pub signatures: Vec<(String, usize)>,
    pub worker_kills: Vec<String>,
    pub concurrency_errors: usize,
}

/// Removes numbers, quoted values and emails, to group lines and avoid repeating personal data.
fn normalize(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut quote: Option<char> = None;
    let mut last_digit = false;
    for c in message.chars() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
                out.push_str("…'");
            }
            continue;
        }
        if c == '\'' || c == '"' {
            quote = Some(c);
            out.push('\'');
            continue;
        }
        if c.is_ascii_digit() {
            if !last_digit {
                out.push('#');
            }
            last_digit = true;
            continue;
        }
        last_digit = false;
        out.push(c);
    }
    let words: Vec<String> = out
        .split_whitespace()
        .map(|w| {
            if w.contains('@') {
                "<email>".to_string()
            } else {
                w.to_string()
            }
        })
        .collect();
    let joined = words.join(" ");
    joined.chars().take(120).collect()
}

/// Splits `2026-11-05 10:00:00,123 42 ERROR db logger: message`.
fn parse_line(line: &str) -> Option<(&str, &str, &str)> {
    let mut parts = line.splitn(6, ' ');
    let date = parts.next()?;
    if date.len() != 10 || date.as_bytes().get(4) != Some(&b'-') {
        return None;
    }
    let _time = parts.next()?;
    let _pid = parts.next()?;
    let level = parts.next()?;
    let _db = parts.next()?;
    let rest = parts.next()?;
    let (logger, message) = rest.split_once(": ").unwrap_or((rest, ""));
    Some((level, logger, message))
}

/// Log wrappers such as compose add a prefix (`odoo-1  | 2026-...`), so start at the timestamp.
fn strip_prefix(line: &str) -> &str {
    let bytes = line.as_bytes();
    let is_date = |w: &[u8]| {
        w[4] == b'-'
            && w[7] == b'-'
            && w.iter()
                .enumerate()
                .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
    };
    match bytes.windows(10).position(is_date) {
        Some(start) => &line[start..],
        None => line,
    }
}

pub fn analyze(source: &str, text: &str) -> LogData {
    let mut data = LogData {
        source: source.to_string(),
        ..LogData::default()
    };
    let mut counts: HashMap<String, usize> = HashMap::new();
    for line in text.lines() {
        data.lines += 1;
        let clean = strip_prefix(line);
        let lower = clean.to_ascii_lowercase();
        if lower.contains("deadlock detected")
            || lower.contains("could not serialize access")
            || lower.contains("serializationfailure")
        {
            data.concurrency_errors += 1;
        }
        let Some((level, logger, message)) = parse_line(clean) else {
            continue;
        };
        let kill = lower.contains("virtual memory limit")
            || lower.contains("worker (")
                && (lower.contains("timeout") || lower.contains("memory limit"))
            || lower.contains("cpu time limit")
            || lower.contains("real time limit");
        if kill && data.worker_kills.len() < 5 {
            data.worker_kills.push(normalize(message));
        }
        if level == "ERROR" || level == "CRITICAL" {
            data.errors += 1;
            *counts
                .entry(format!("{logger}: {}", normalize(message)))
                .or_default() += 1;
        }
    }
    let mut signatures: Vec<_> = counts.into_iter().collect();
    signatures.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    signatures.truncate(5);
    data.signatures = signatures;
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_errors_and_masks_values() {
        let log = "\
2026-11-05 10:00:00,123 42 ERROR prod odoo.http: Failed for 'alice@example.com' on record 1234
2026-11-05 10:00:01,123 42 ERROR prod odoo.http: Failed for 'bob@example.com' on record 99
2026-11-05 10:00:02,123 42 INFO prod odoo.modules: all fine
not a log line
";
        let d = analyze("test", log);
        assert_eq!(d.errors, 2);
        assert_eq!(d.signatures.len(), 1);
        assert_eq!(d.signatures[0].1, 2);
        assert!(!d.signatures[0].0.contains("alice"));
        assert!(!d.signatures[0].0.contains("1234"));
    }

    #[test]
    fn handles_compose_prefix_and_counts_kills_and_deadlocks() {
        let log = "\
odoo-1  | 2026-11-05 10:00:00,123 42 WARNING prod odoo.service.server: Worker (123) timeout after CPU time limit
2026-11-05 10:00:00,123 42 ERROR prod odoo.sql_db: bad query: deadlock detected
";
        let d = analyze("test", log);
        assert_eq!(d.worker_kills.len(), 1);
        assert_eq!(d.concurrency_errors, 1);
        assert_eq!(d.errors, 1);
    }

    #[test]
    fn normalize_handles_unterminated_quotes_and_unicode() {
        assert_eq!(normalize("value 'unterminated"), "value '");
        assert!(normalize("año 2026 ñandú").contains('#'));
    }
}
