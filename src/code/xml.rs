//! XML views, templates and data files.
use super::Hit;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

fn attrs(element: &BytesStart<'_>) -> Vec<(String, String)> {
    element
        .attributes()
        .with_checks(false)
        .flatten()
        .map(|a| {
            let key = String::from_utf8_lossy(a.key.as_ref()).into_owned();
            let value = String::from_utf8_lossy(&a.value).into_owned();
            (key, value)
        })
        .collect()
}

fn get<'a>(attrs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

struct Walker<'s> {
    src: &'s str,
    starts: Vec<usize>,
    hits: Vec<Hit>,
    record_stack: Vec<String>,
    /// The `<field name="...">` whose text we are reading, with the line where it started.
    open_field: Option<(String, usize, String)>,
    depth: usize,
    field_depth: usize,
}

impl Walker<'_> {
    fn line(&self, offset: usize) -> usize {
        let offset = offset.min(self.src.len());
        match self.starts.binary_search(&offset) {
            Ok(i) => i + 1,
            Err(i) => i,
        }
    }

    fn hit(&mut self, rule: &'static str, line: usize, detail: impl Into<String>) {
        self.hits.push(Hit {
            rule,
            file: String::new(),
            line,
            detail: detail.into(),
        });
    }

    fn current_model(&self) -> &str {
        self.record_stack.last().map_or("", String::as_str)
    }

    fn element(&mut self, tag: &str, attributes: &[(String, String)], line: usize) {
        if tag == "tree" {
            self.hit("UPG005", line, "<tree>");
        }
        if tag == "record" {
            match get(attributes, "model") {
                Some("ir.model.access") => {
                    self.hit("UPG001", line, "<record model=\"ir.model.access\">")
                }
                Some("ir.rule") => self.hit("UPG001", line, "<record model=\"ir.rule\">"),
                _ => {}
            }
        }
        for (key, value) in attributes {
            match key.as_str() {
                "attrs" if value.trim_start().starts_with('{') => {
                    self.hit("UPG004", line, format!("<{tag} attrs=...>"))
                }
                "states" if matches!(tag, "field" | "button") => {
                    self.hit("UPG004", line, format!("<{tag} states=...>"))
                }
                "t-raw" => {
                    self.hit(
                        "XML001",
                        line,
                        format!("t-raw=\"{}\"", value.chars().take(50).collect::<String>()),
                    );
                }
                "t-esc" => self.hit("UPG015", line, "t-esc"),
                "t-name" if value == "kanban-box" => {
                    self.hit("UPG013", line, "t-name=\"kanban-box\"")
                }
                _ => {}
            }
        }
        if tag == "field" {
            match get(attributes, "name") {
                Some(name @ ("numbercall" | "doall")) if self.current_model() == "ir.cron" => {
                    self.hit("UPG007", line, format!("ir.cron field {name}"));
                }
                Some("groups_id") => self.hit("UPG011", line, "field groups_id"),
                Some("category_id") if self.current_model() == "res.groups" => {
                    self.hit("UPG012", line, "res.groups field category_id");
                }
                _ => {}
            }
        }
    }

    fn close_field(&mut self) {
        let Some((name, line, text)) = self.open_field.take() else {
            return;
        };
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        if name == "view_mode" && compact.split(',').any(|m| m == "tree") {
            self.hit("UPG005", line, "view_mode contains tree");
        }
        if name == "domain_force" {
            let normalized = compact.replace('"', "'");
            if normalized == "[(1,'=',1)]" {
                self.hit("XML002", line, "domain_force = [(1, '=', 1)]");
            }
        }
    }
}

/// Returns the findings, plus a parse error with its line if the file is malformed.
pub fn scan(src: &str) -> (Vec<Hit>, Option<(usize, String)>) {
    let mut starts = vec![0];
    starts.extend(
        src.bytes()
            .enumerate()
            .filter(|(_, b)| *b == b'\n')
            .map(|(i, _)| i + 1),
    );
    let mut walker = Walker {
        src,
        starts,
        hits: Vec::new(),
        record_stack: Vec::new(),
        open_field: None,
        depth: 0,
        field_depth: 0,
    };
    let mut reader = Reader::from_str(src);
    reader.config_mut().check_end_names = true;
    loop {
        let before = reader.buffer_position() as usize;
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                let attributes = attrs(&e);
                let line = walker.line(before);
                walker.element(&tag, &attributes, line);
                walker.depth += 1;
                if tag == "record" {
                    walker
                        .record_stack
                        .push(get(&attributes, "model").unwrap_or("").to_string());
                }
                if tag == "field" && walker.open_field.is_none() {
                    if let Some(name @ ("view_mode" | "domain_force")) = get(&attributes, "name") {
                        walker.open_field = Some((name.to_string(), line, String::new()));
                        walker.field_depth = walker.depth;
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                let attributes = attrs(&e);
                let line = walker.line(before);
                walker.element(&tag, &attributes, line);
            }
            Ok(Event::Text(t)) => {
                if let Some((_, _, text)) = walker.open_field.as_mut() {
                    text.push_str(&String::from_utf8_lossy(t.as_ref()));
                }
            }
            Ok(Event::CData(t)) => {
                if let Some((_, _, text)) = walker.open_field.as_mut() {
                    text.push_str(&String::from_utf8_lossy(t.as_ref()));
                }
            }
            Ok(Event::End(e)) => {
                if walker.open_field.is_some() && walker.depth == walker.field_depth {
                    walker.close_field();
                }
                walker.depth = walker.depth.saturating_sub(1);
                if e.name().as_ref() == b"record" {
                    walker.record_stack.pop();
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                let line = walker.line(reader.buffer_position() as usize);
                return (walker.hits, Some((line, e.to_string())));
            }
        }
    }
    (walker.hits, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(src: &str) -> Vec<&'static str> {
        let (hits, err) = scan(src);
        assert!(err.is_none(), "{err:?}");
        hits.iter().map(|h| h.rule).collect()
    }

    #[test]
    fn view_rules() {
        assert_eq!(
            rules("<odoo><field name='a' attrs=\"{'invisible': []}\"/></odoo>"),
            ["UPG004"]
        );
        assert_eq!(rules("<odoo><button states='draft'/></odoo>"), ["UPG004"]);
        assert_eq!(
            rules("<odoo><tree><field name='a'/></tree></odoo>"),
            ["UPG005"]
        );
        assert_eq!(rules("<odoo><t t-name='kanban-box'/></odoo>"), ["UPG013"]);
        assert_eq!(
            rules("<odoo><span t-raw='x'/><span t-esc='y'/></odoo>"),
            ["XML001", "UPG015"]
        );
    }

    #[test]
    fn not_every_attrs_attribute_is_the_old_view_syntax() {
        assert!(rules("<odoo><Comp attrs='props.attrs'/></odoo>").is_empty());
        assert!(rules("<odoo><div states='x'/></odoo>").is_empty());
    }

    #[test]
    fn record_rules_depend_on_the_model() {
        assert_eq!(rules("<odoo><record model='ir.cron' id='c'><field name='numbercall'>1</field></record></odoo>"), ["UPG007"]);
        assert!(rules(
            "<odoo><record model='x.y' id='c'><field name='numbercall'>1</field></record></odoo>"
        )
        .is_empty());
        assert_eq!(rules("<odoo><record model='res.groups' id='g'><field name='category_id' ref='a'/></record></odoo>"), ["UPG012"]);
        assert!(rules("<odoo><record model='res.partner' id='g'><field name='category_id' ref='a'/></record></odoo>").is_empty());
        assert_eq!(
            rules("<odoo><record model='ir.model.access' id='a'/></odoo>"),
            ["UPG001"]
        );
    }

    #[test]
    fn field_text_rules_ignore_formatting() {
        assert_eq!(rules("<odoo><record model='ir.actions.act_window' id='a'><field name='view_mode'>tree, form</field></record></odoo>"), ["UPG005"]);
        assert!(rules("<odoo><record model='ir.actions.act_window' id='a'><field name='view_mode'>list,form</field></record></odoo>").is_empty());
        let rule = "<odoo><record model='ir.rule' id='a'><field name='domain_force'>[ (1, \"=\", 1) ]</field></record></odoo>";
        assert_eq!(rules(rule), ["UPG001", "XML002"]);
    }

    #[test]
    fn lines_are_correct_and_errors_are_reported() {
        let (hits, _) = scan("<odoo>\n\n  <tree/>\n</odoo>");
        assert_eq!(hits[0].line, 3);
        let (_, err) = scan("<odoo>\n<a></b>\n</odoo>");
        assert!(err.is_some());
    }
}
