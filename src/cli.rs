//! Command-line parsing.
//!
//! Mirrors the documented option surface and the option string
//! `46a:A:c:C:d:D:f:Fhjn:p:Pqr:R:sS:t:T:u:vx`. Parsing is hand-written to keep
//! the crate dependency-light.

use std::fmt;
use std::path::PathBuf;

/// Authentication method selected with `-a`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthType {
    Pap,
    Chap,
    None,
}

/// Parsed command-line options.
#[derive(Debug, Default, Clone)]
pub struct Options {
    pub auth_type: Option<AuthType>,
    pub accounting: Option<String>,
    pub count: Option<u64>,
    pub copy_attrs: Option<String>,
    pub dict_dir: Option<PathBuf>,
    pub delays_file: Option<PathBuf>,
    pub input_files: Vec<PathBuf>,
    pub framed_ip: bool,
    pub help: bool,
    pub json_summary: bool,
    pub message_authenticator: Option<String>,
    pub rate: Option<u64>,
    pub parallel: Option<usize>,
    pub persec: bool,
    pub quiet: bool,
    pub retries: Option<u32>,
    pub realm: Option<String>,
    pub summary: bool,
    pub secret_file: Option<PathBuf>,
    pub timeout: Option<f64>,
    pub template_files: Vec<PathBuf>,
    pub users: Option<u64>,
    pub version: bool,
    pub debug: u32,
    pub ipv4: bool,
    pub ipv6: bool,
    pub positional: Vec<String>,
}

/// CLI parsing error.
#[derive(Debug)]
pub struct CliError {
    pub message: String,
}

impl CliError {
    fn new(message: impl Into<String>) -> Self {
        CliError {
            message: message.into(),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CliError {}

/// True when the option letter takes a value.
fn takes_value(c: char) -> bool {
    matches!(
        c,
        'a' | 'A'
            | 'c'
            | 'C'
            | 'd'
            | 'D'
            | 'f'
            | 'm'
            | 'n'
            | 'p'
            | 'r'
            | 'R'
            | 'S'
            | 't'
            | 'T'
            | 'u'
    )
}

/// Parse arguments (without the program name).
pub fn parse<I, S>(args: I) -> Result<Options, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args: Vec<String> = args.into_iter().map(Into::into).collect();
    let mut opts = Options::default();
    let mut i = 0;
    let mut only_positional = false;
    while i < args.len() {
        let arg = args[i].clone();
        if only_positional || arg == "-" || !arg.starts_with('-') {
            opts.positional.push(arg);
            i += 1;
            continue;
        }
        if arg == "--" {
            only_positional = true;
            i += 1;
            continue;
        }
        if let Some(long) = arg.strip_prefix("--") {
            match long {
                "help" => opts.help = true,
                "version" => opts.version = true,
                "json" => opts.json_summary = true,
                other => return Err(CliError::new(format!("unknown option '--{other}'"))),
            }
            i += 1;
            continue;
        }

        let chars: Vec<char> = arg[1..].chars().collect();
        let mut j = 0;
        while j < chars.len() {
            let c = chars[j];
            if takes_value(c) {
                let inline: String = chars[j + 1..].iter().collect();
                let value = if !inline.is_empty() {
                    inline
                } else {
                    i += 1;
                    args.get(i)
                        .cloned()
                        .ok_or_else(|| CliError::new(format!("option -{c} requires a value")))?
                };
                apply_value(&mut opts, c, value)?;
                break;
            }
            apply_flag(&mut opts, c)?;
            j += 1;
        }
        i += 1;
    }
    Ok(opts)
}

fn apply_flag(opts: &mut Options, c: char) -> Result<(), CliError> {
    match c {
        '4' => opts.ipv4 = true,
        '6' => opts.ipv6 = true,
        'F' => opts.framed_ip = true,
        'h' => opts.help = true,
        'j' => opts.json_summary = true,
        'P' => opts.persec = true,
        'q' => opts.quiet = true,
        's' => opts.summary = true,
        'v' => opts.version = true,
        'x' => opts.debug += 1,
        other => return Err(CliError::new(format!("unknown option '-{other}'"))),
    }
    Ok(())
}

fn apply_value(opts: &mut Options, c: char, value: String) -> Result<(), CliError> {
    let parse_u64 = |v: &str| {
        v.parse::<u64>()
            .map_err(|_| CliError::new(format!("invalid number '{v}'")))
    };
    match c {
        'a' => {
            opts.auth_type = Some(match value.as_str() {
                "pap" => AuthType::Pap,
                "chap" => AuthType::Chap,
                "none" => AuthType::None,
                other => return Err(CliError::new(format!("unknown auth type '{other}'"))),
            })
        }
        'A' => opts.accounting = Some(value),
        'c' => opts.count = Some(parse_u64(&value)?),
        'C' => opts.copy_attrs = Some(value),
        'd' => opts.dict_dir = Some(PathBuf::from(value)),
        'D' => opts.delays_file = Some(PathBuf::from(value)),
        'f' => opts.input_files.push(PathBuf::from(value)),
        'm' => opts.message_authenticator = Some(value),
        'n' => opts.rate = Some(parse_u64(&value)?),
        'p' => opts.parallel = Some(parse_u64(&value)? as usize),
        'r' => opts.retries = Some(parse_u64(&value)? as u32),
        'R' => opts.realm = Some(value),
        'S' => opts.secret_file = Some(PathBuf::from(value)),
        't' => {
            opts.timeout = Some(
                value
                    .parse::<f64>()
                    .map_err(|_| CliError::new(format!("invalid timeout '{value}'")))?,
            )
        }
        'T' => opts.template_files.push(PathBuf::from(value)),
        'u' => opts.users = Some(parse_u64(&value)?),
        _ => unreachable!("takes_value was checked"),
    }
    Ok(())
}

/// Map a command word (or decimal code) to a RADIUS packet code.
pub fn command_code(command: &str) -> Result<u8, CliError> {
    use crate::packet::{
        ACCESS_REQUEST, ACCOUNTING_REQUEST, COA_REQUEST, DISCONNECT_REQUEST, STATUS_SERVER,
    };
    match command {
        "auth" => Ok(ACCESS_REQUEST),
        "acct" => Ok(ACCOUNTING_REQUEST),
        "status" => Ok(STATUS_SERVER),
        "coa" => Ok(COA_REQUEST),
        "disconnect" => Ok(DISCONNECT_REQUEST),
        "auto" => Ok(ACCESS_REQUEST), // refined by input inspection in main
        other => {
            let code: u8 = other
                .parse()
                .map_err(|_| CliError::new(format!("unknown command '{other}'")))?;
            if code == 0 {
                return Err(CliError::new("command code must be 1..255"));
            }
            Ok(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flags_and_values() {
        let o = parse([
            "-q", "-x", "-x", "-n", "1000", "-p", "50", "host", "auth", "s3cr3t",
        ])
        .unwrap();
        assert!(o.quiet);
        assert_eq!(o.debug, 2);
        assert_eq!(o.rate, Some(1000));
        assert_eq!(o.parallel, Some(50));
        assert_eq!(o.positional, vec!["host", "auth", "s3cr3t"]);
    }

    #[test]
    fn supports_inline_values_and_clustering() {
        let o = parse(["-n1000", "-qp10"]).unwrap();
        assert_eq!(o.rate, Some(1000));
        assert!(o.quiet);
        assert_eq!(o.parallel, Some(10));
    }

    #[test]
    fn parses_auth_and_accounting() {
        let o = parse(["-a", "chap", "-A", "10,600", "-r", "3", "-t", "2.5"]).unwrap();
        assert_eq!(o.auth_type, Some(AuthType::Chap));
        assert_eq!(o.accounting.as_deref(), Some("10,600"));
        assert_eq!(o.retries, Some(3));
        assert_eq!(o.timeout, Some(2.5));
    }

    #[test]
    fn repeated_files_and_debug() {
        let o = parse(["-f", "a.txt", "-f", "b.csv", "-xxx"]).unwrap();
        assert_eq!(
            o.input_files,
            vec![PathBuf::from("a.txt"), PathBuf::from("b.csv")]
        );
        assert_eq!(o.debug, 3);
    }

    #[test]
    fn rejects_unknown_option() {
        assert!(parse(["-Z"]).is_err());
        assert!(parse(["-n"]).is_err());
    }

    #[test]
    fn parses_message_authenticator_mode() {
        assert_eq!(
            parse(["-m", "yes"])
                .unwrap()
                .message_authenticator
                .as_deref(),
            Some("yes")
        );
        assert_eq!(
            parse(["-mno"]).unwrap().message_authenticator.as_deref(),
            Some("no")
        );
        assert_eq!(
            parse(Vec::<String>::new()).unwrap().message_authenticator,
            None
        );
    }

    #[test]
    fn command_codes() {
        assert_eq!(command_code("auth").unwrap(), 1);
        assert_eq!(command_code("acct").unwrap(), 4);
        assert_eq!(command_code("status").unwrap(), 12);
        assert_eq!(command_code("coa").unwrap(), 43);
        assert_eq!(command_code("disconnect").unwrap(), 40);
        assert_eq!(command_code("7").unwrap(), 7);
        assert!(command_code("0").is_err());
        assert!(command_code("nope").is_err());
    }
}
