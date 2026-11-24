//! Input parsing: FreeRADIUS-style attribute files and the two-column CSV
//! form, plus the quoting rules described in the tool's manual.
//!
//! Parsing is a setup-time cost; the output is a list of packet templates, each
//! a list of `(attribute-name, raw-value)` pairs.

use std::fmt;
use std::fs;
use std::path::Path;

/// One parsed input packet: attribute name / raw value pairs.
pub type Record = Vec<(String, String)>;

/// Input parsing error.
#[derive(Debug)]
pub struct InputError {
    pub message: String,
}

impl InputError {
    fn new(message: impl Into<String>) -> Self {
        InputError {
            message: message.into(),
        }
    }
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for InputError {}

/// Parse a FreeRADIUS-style attribute file. Blank lines separate packets;
/// `#` starts a comment.
pub fn parse_attribute_text(text: &str) -> Result<Vec<Record>, InputError> {
    let mut records = Vec::new();
    let mut current: Record = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            if !current.is_empty() {
                records.push(std::mem::take(&mut current));
            }
            continue;
        }
        let (name, value) = split_assignment(line).ok_or_else(|| {
            InputError::new(format!("line {}: missing '=' in '{line}'", lineno + 1))
        })?;
        current.push((name, dequote(&value)));
    }
    if !current.is_empty() {
        records.push(current);
    }
    Ok(records)
}

/// Parse a two-column CSV (`name,password`) into `User-Name` / `User-Password`
/// attribute records.
pub fn parse_csv_text(text: &str) -> Result<Vec<Record>, InputError> {
    let mut records = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        if raw.trim().is_empty() {
            continue;
        }
        let fields = parse_csv_row(raw);
        if fields.len() < 2 {
            return Err(InputError::new(format!(
                "line {}: expected 'name,password', got {} field(s)",
                lineno + 1,
                fields.len()
            )));
        }
        records.push(vec![
            ("User-Name".to_string(), fields[0].clone()),
            ("User-Password".to_string(), fields[1].clone()),
        ]);
    }
    Ok(records)
}

/// Parse a single input file, choosing the CSV form by `.csv` extension.
pub fn parse_file(path: &Path) -> Result<Vec<Record>, InputError> {
    let text = fs::read_to_string(path)
        .map_err(|e| InputError::new(format!("cannot read {}: {e}", path.display())))?;
    let is_csv = path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("csv"))
        .unwrap_or(false);
    if is_csv {
        parse_csv_text(&text)
    } else {
        parse_attribute_text(&text)
    }
}

/// Parse and concatenate several input files, in order.
pub fn parse_files(paths: &[impl AsRef<Path>]) -> Result<Vec<Record>, InputError> {
    let mut all = Vec::new();
    for p in paths {
        all.extend(parse_file(p.as_ref())?);
    }
    Ok(all)
}

/// Remove a `#` comment, respecting double-quoted sections.
fn strip_comment(line: &str) -> &str {
    let mut in_quotes = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            '#' if !in_quotes => return &line[..i],
            _ => {}
        }
    }
    line
}

/// Split `name = value` (also accepting `:=`, `+=`, `==`).
fn split_assignment(line: &str) -> Option<(String, String)> {
    let (name, value) = line.split_once('=')?;
    let name = name.trim();
    let (name, value) = match name.strip_suffix([':', '+', '-']) {
        Some(name) => (name.trim_end(), value),
        None => (name, value.strip_prefix('=').unwrap_or(value)),
    };
    if name.is_empty() {
        return None;
    }
    Some((name.to_string(), value.trim().to_string()))
}

/// Apply the documented quoting rules: a value wrapped in double quotes has
/// those removed; `\"`, `\\` and a doubled `""` become a single character.
pub fn dequote(value: &str) -> String {
    let bytes = value.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'"' || bytes[bytes.len() - 1] != b'"' {
        return value.to_string();
    }
    let inner = &value[1..value.len() - 1];
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            },
            '"' if chars.peek() == Some(&'"') => {
                chars.next();
                out.push('"');
            }
            other => out.push(other),
        }
    }
    out
}

/// Parse one CSV row into fields, honoring double-quote quoting.
fn parse_csv_row(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;
    let mut started = false;
    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
        } else {
            match c {
                '"' if !started => {
                    in_quotes = true;
                    started = true;
                }
                ',' => {
                    fields.push(std::mem::take(&mut field));
                    started = false;
                }
                _ => {
                    field.push(c);
                    started = true;
                }
            }
        }
    }
    fields.push(field);
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_two_packets_separated_by_blank_line() {
        let text = "\
# a comment
User-Name = \"alice\"
User-Password = \"secret\"

User-Name = bob
NAS-IP-Address = 10.0.0.1
";
        let recs = parse_attribute_text(text).unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0][0], ("User-Name".to_string(), "alice".to_string()));
        assert_eq!(recs[0][1].1, "secret");
        assert_eq!(recs[1][0].1, "bob");
        assert_eq!(
            recs[1][1],
            ("NAS-IP-Address".to_string(), "10.0.0.1".to_string())
        );
    }

    #[test]
    fn supports_colon_equals_operator() {
        let recs = parse_attribute_text("User-Name := \"x\"\n").unwrap();
        assert_eq!(recs[0][0], ("User-Name".to_string(), "x".to_string()));
    }

    #[test]
    fn keeps_hash_inside_quotes() {
        let recs = parse_attribute_text("User-Name = \"a#b\"\n").unwrap();
        assert_eq!(recs[0][0].1, "a#b");
    }

    #[test]
    fn dequote_handles_escapes_and_doubled_quotes() {
        assert_eq!(dequote("\"a\\\"b\""), "a\"b");
        assert_eq!(dequote("\"a\"\"b\""), "a\"b");
        assert_eq!(dequote("\"a\\\\b\""), "a\\b");
        assert_eq!(dequote("plain"), "plain");
    }

    #[test]
    fn parses_csv_with_quoting() {
        let text = "bob,hello\nalice,\"pa,ss\"\n\"carol\",\"she said \"\"hi\"\"\"\n";
        let recs = parse_csv_text(text).unwrap();
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0][0].1, "bob");
        assert_eq!(recs[0][1].1, "hello");
        assert_eq!(recs[1][1].1, "pa,ss");
        assert_eq!(recs[2][0].1, "carol");
        assert_eq!(recs[2][1].1, "she said \"hi\"");
    }

    #[test]
    fn csv_rejects_single_field() {
        assert!(parse_csv_text("onlyone\n").is_err());
    }

    #[test]
    fn missing_assignment_is_an_error() {
        assert!(parse_attribute_text("User-Name \"x\"\n").is_err());
    }
}
