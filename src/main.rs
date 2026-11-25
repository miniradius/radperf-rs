#![forbid(unsafe_code)]

use radperf_rs::accounting::{self, AcctConfig};
use radperf_rs::cli::{self, AuthType, Options};
use radperf_rs::client::{Client, ClientConfig};
use radperf_rs::dict::Dictionary;
use radperf_rs::input;
use radperf_rs::output;
use radperf_rs::packet;
use radperf_rs::request::{AuthMode, MsgAuthMode, Template};
use std::io::Read;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("radperf: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    // Stop cleanly on Ctrl+C so the summary is still printed.
    radperf_rs::signals::install();

    let opts = cli::parse(args.iter().cloned()).map_err(|e| e.to_string())?;

    if opts.help {
        output::print_usage("radperf");
        return Ok(());
    }
    if opts.version {
        println!("radperf {} (miniradius/radperf-rs)", radperf_rs::VERSION);
        return Ok(());
    }
    if opts.positional.len() < 2 {
        output::print_usage("radperf");
        return Err("server and command are required".to_string());
    }

    let server_spec = &opts.positional[0];
    let command = &opts.positional[1];
    let secret = resolve_secret(&opts)?;

    // Load the dictionary.
    let dict_dir = resolve_dict_dir(&opts)?;
    if opts.debug >= 2 {
        eprintln!(
            "Reading dictionary: \"{}\"",
            dict_dir.join("dictionary").display()
        );
    }
    let dict = Dictionary::load_dir(&dict_dir)
        .map_err(|e| format!("dictionary error: {e} (dir: {})", dict_dir.display()))?;

    let records = load_records(&opts)?;

    if records.is_empty() {
        return Err("no input packets (use -f, stdin, or -u)".to_string());
    }

    // Resolve the packet code, refining `auto` from the input.
    let mut code = cli::command_code(command).map_err(|e| e.to_string())?;
    if command == "auto" {
        let has_accounting = records
            .iter()
            .flatten()
            .any(|(name, _)| name == "Acct-Status-Type");
        code = if has_accounting {
            packet::ACCOUNTING_REQUEST
        } else {
            packet::ACCESS_REQUEST
        };
    }
    validate_auth(&opts, code)?;

    // Build templates.
    let auth_mode = match opts.auth_type {
        Some(AuthType::Chap) => AuthMode::Chap,
        _ => AuthMode::Pap,
    };
    // `-a none` skips authentication and runs the accounting flow directly.
    let accounting_direct = opts.auth_type == Some(AuthType::None);
    let templates: Vec<Template> = records
        .iter()
        .map(|record| Template::from_pairs_with_auth(&dict, code, record, auth_mode))
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;

    // BlastRADIUS mitigation: add a Message-Authenticator where configured.
    let msg_auth = parse_msg_auth(&opts)?;
    let mut templates = templates;
    for template in &mut templates {
        let add = match msg_auth {
            // FreeRADIUS only requires a Message-Authenticator on Access-Request
            // (and Status/CoA/Disconnect); Accounting-Requests do not carry one.
            MsgAuthMode::Auto => code != packet::ACCOUNTING_REQUEST,
            MsgAuthMode::Never => false,
        };
        if add {
            template.ensure_message_authenticator();
        }
    }

    // Build the job list: each input packet `count` times (default 1).
    let count = opts.count.unwrap_or(1).max(1);
    let mut jobs = Vec::with_capacity(templates.len() * count as usize);
    for _ in 0..count {
        for i in 0..templates.len() {
            jobs.push(i as u32);
        }
    }
    if accounting_direct {
        // No authentication phase; the accounting flow drives the run.
        jobs.clear();
    }

    // Accounting flow (-A / -C / -F): used for Access-Request runs and for
    // `-a none`, which skips authentication.
    let accounting = if accounting_direct || code == packet::ACCESS_REQUEST {
        parse_accounting(&opts)?
    } else {
        None
    };
    let acct_copy_types = build_copy_types(&opts, &dict)?;
    let acct_bases: Vec<Vec<u8>> = templates
        .iter()
        .map(|t| accounting::base_attributes(t.attributes()))
        .collect();

    let server = resolve_server(server_spec, default_port(code), opts.ipv6)
        .map_err(|e| format!("cannot resolve server '{server_spec}': {e}"))?;
    let acct_server = if accounting.is_some() {
        Some(
            resolve_server(server_spec, 1813, opts.ipv6)
                .map_err(|e| format!("cannot resolve accounting server '{server_spec}': {e}"))?,
        )
    } else {
        None
    };

    let config = ClientConfig {
        server,
        secret,
        parallel: opts.parallel.unwrap_or(1).max(1),
        rate: opts.rate.unwrap_or(0),
        retries: opts.retries.unwrap_or(5),
        timeout: Duration::from_secs_f64(opts.timeout.unwrap_or(5.0)),
        quiet: opts.quiet,
        debug: opts.debug,
        collect_stats: opts.summary,
        json_summary: opts.json_summary,
        print_summary: opts.summary,
        delays: opts.delays_file.clone(),
        persec: opts.persec,
        accounting,
        accounting_direct,
        acct_server,
        acct_copy_types,
        acct_bases,
    };

    let start = Instant::now();
    let mut client = Client::new(config, templates, jobs).map_err(|e| e.to_string())?;
    let result = client.run();
    let stats = result.as_ref().unwrap_or_else(|_| client.stats());
    let elapsed = start.elapsed();

    if !opts.quiet && (opts.summary || opts.json_summary) {
        let _ = output::print_summary(stats, elapsed, opts.json_summary, &mut std::io::stdout());
    } else if !opts.quiet && opts.debug > 0 {
        let _ = output::print_summary(stats, elapsed, false, &mut std::io::stdout());
    }
    result.map(|_| ()).map_err(|e| e.to_string())
}

fn validate_auth(opts: &Options, code: u8) -> Result<(), String> {
    if opts.auth_type == Some(AuthType::None) && opts.accounting.is_none() {
        return Err("-a none requires -A delay,lifetime".to_string());
    }
    if code == packet::ACCESS_REQUEST && opts.accounting.is_some() {
        // Accepted: -A enables the accounting phase after Access-Accept.
    }
    Ok(())
}

fn resolve_secret(opts: &Options) -> Result<Vec<u8>, String> {
    if let Some(path) = &opts.secret_file {
        let raw =
            std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let trimmed: Vec<u8> = raw
            .iter()
            .copied()
            .take_while(|&b| b != b'\n' && b != b'\r')
            .collect();
        if trimmed.is_empty() {
            return Err("secret file is empty".to_string());
        }
        return Ok(trimmed);
    }
    match opts.positional.get(2) {
        Some(s) if !s.is_empty() => Ok(s.as_bytes().to_vec()),
        _ => Err("a shared secret is required (positional or -S file)".to_string()),
    }
}

fn resolve_dict_dir(opts: &Options) -> Result<PathBuf, String> {
    if let Some(dir) = &opts.dict_dir {
        return Ok(dir.clone());
    }
    if let Ok(env) = std::env::var("FREERADIUS_DICTIONARY_PATH") {
        if !env.is_empty() {
            return Ok(PathBuf::from(env));
        }
    }
    // Default: ../share relative to the executable.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            return Ok(dir.join("../share"));
        }
    }
    Err("no dictionary directory (use -d or FREERADIUS_DICTIONARY_PATH)".to_string())
}

fn load_records(opts: &Options) -> Result<Vec<input::Record>, String> {
    let mut records = if !opts.input_files.is_empty() {
        let mut all = Vec::new();
        for path in &opts.input_files {
            if opts.debug >= 1 {
                eprintln!("Reading file \"{}\" (as RADIUS packets)", path.display());
            }
            let recs = input::parse_file(path).map_err(|e| e.to_string())?;
            if opts.debug >= 1 {
                eprintln!("Read {} packets", recs.len());
            }
            all.extend(recs);
        }
        all
    } else if opts.users.is_some() {
        // `-u` generates its own records; do not block on stdin.
        Vec::new()
    } else {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .map_err(|e| format!("cannot read stdin: {e}"))?;
        input::parse_attribute_text(&text).map_err(|e| e.to_string())?
    };

    let input_count = records.len();
    if let Some(users) = opts.users {
        let suffix = opts.realm.as_deref().unwrap_or_default();
        records.extend((1..=users).map(|i| {
            let name = format!("user{i}{suffix}");
            vec![
                ("User-Name".to_string(), name.clone()),
                ("User-Password".to_string(), name),
            ]
        }));
    }

    // -T template files: attributes appended to every request.
    if !opts.template_files.is_empty() {
        let mut base: input::Record = Vec::new();
        for path in &opts.template_files {
            let parsed = input::parse_file(path).map_err(|e| e.to_string())?;
            for record in parsed {
                base.extend(record);
            }
        }
        for record in &mut records {
            record.extend(base.clone());
        }
    }
    // For file and stdin records, retain the existing realm handling.
    if let Some(realm) = &opts.realm {
        for record in records.iter_mut().take(input_count) {
            for (name, value) in record.iter_mut() {
                if name == "User-Name" && !value.contains('@') {
                    value.push('@');
                    value.push_str(realm);
                }
            }
        }
    }
    Ok(records)
}

/// Parse `-m` into a Message-Authenticator mode.
fn parse_msg_auth(opts: &Options) -> Result<MsgAuthMode, String> {
    match opts.message_authenticator.as_deref() {
        None | Some("auto") | Some("yes") | Some("always") | Some("on") => Ok(MsgAuthMode::Auto),
        Some("no") | Some("never") | Some("off") => Ok(MsgAuthMode::Never),
        Some(other) => Err(format!(
            "invalid -m value '{other}' (expected auto, yes or no)"
        )),
    }
}

/// Parse `-A delay,lifetime` into an accounting configuration.
fn parse_accounting(opts: &Options) -> Result<Option<AcctConfig>, String> {
    let Some(spec) = &opts.accounting else {
        return Ok(None);
    };
    let (delay, lifetime) = spec
        .split_once(',')
        .ok_or_else(|| format!("-A expects 'delay,lifetime', got '{spec}'"))?;
    let delay = delay
        .trim()
        .parse::<f64>()
        .ok()
        .and_then(|s| Duration::try_from_secs_f64(s).ok())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| format!("accounting delay must be positive, got '{delay}'"))?;
    let lifetime = lifetime
        .trim()
        .parse::<f64>()
        .ok()
        .and_then(|s| Duration::try_from_secs_f64(s).ok())
        .filter(|d| Instant::now().checked_add(*d).is_some())
        .ok_or_else(|| format!("invalid accounting lifetime '{lifetime}'"))?;
    Ok(Some(AcctConfig {
        delay,
        lifetime,
        framed_ip: opts.framed_ip,
    }))
}

/// Attribute types copied from the Access-Accept: always `Class`, plus `-C`.
fn build_copy_types(opts: &Options, dict: &Dictionary) -> Result<Vec<u8>, String> {
    let mut types = vec![accounting::ATTR_CLASS];
    if opts.framed_ip {
        // -F: also copy Framed-IP-Address from the Access-Accept.
        types.push(accounting::ATTR_FRAMED_IP_ADDRESS);
    }
    if let Some(list) = &opts.copy_attrs {
        for name in list.split(',') {
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            let attr = dict
                .attr_by_name(name)
                .ok_or_else(|| format!("unknown attribute '{name}' in -C"))?;
            if attr.vendor != 0 {
                return Err(format!("-C: vendor attribute '{name}' is not supported"));
            }
            let typ = attr.number as u8;
            if !types.contains(&typ) {
                types.push(typ);
            }
        }
    }
    Ok(types)
}

fn default_port(code: u8) -> u16 {
    match code {
        packet::ACCOUNTING_REQUEST => 1813,
        _ => 1812,
    }
}

/// Resolve `host`, `host:port` or `[v6]:port` to a socket address.
fn resolve_server(spec: &str, default_port: u16, prefer6: bool) -> Result<SocketAddr, String> {
    let (host, port) = split_host_port(spec, default_port);
    let addrs: Vec<SocketAddr> = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .collect();
    if addrs.is_empty() {
        return Err("no addresses found".to_string());
    }
    let wanted = if prefer6 {
        addrs.iter().find(|a| a.is_ipv6())
    } else {
        addrs.iter().find(|a| a.is_ipv4())
    };
    Ok(*wanted.or_else(|| addrs.first()).unwrap())
}

fn split_host_port(spec: &str, default_port: u16) -> (String, u16) {
    if let Some(rest) = spec.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = rest[..end].to_string();
            let port = rest[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default_port);
            return (host, port);
        }
    }
    match spec.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() && !host.contains(':') => {
            (host.to_string(), port.parse().unwrap())
        }
        _ => (spec.to_string(), default_port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounting_rejects_invalid_durations() {
        for spec in ["0,1", "-1,1", "NaN,1", "1,-1", "1,inf", "1,1e100"] {
            let opts = Options {
                accounting: Some(spec.to_string()),
                ..Options::default()
            };
            assert!(parse_accounting(&opts).is_err(), "{spec}");
        }
    }

    #[test]
    fn splits_host_and_port() {
        assert_eq!(
            split_host_port("localhost", 1812),
            ("localhost".to_string(), 1812)
        );
        assert_eq!(
            split_host_port("host:1813", 1812),
            ("host".to_string(), 1813)
        );
        assert_eq!(
            split_host_port("[::1]:1812", 1813),
            ("::1".to_string(), 1812)
        );
        assert_eq!(
            split_host_port("2001:db8::1", 1812),
            ("2001:db8::1".to_string(), 1812)
        );
    }
}
