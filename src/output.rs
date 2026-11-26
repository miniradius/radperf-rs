//! Result reporting: human-readable summary and a JSON summary.

use crate::stats::Stats;
use std::io::Write;
use std::time::Duration;

/// Write the run summary, in the reference tool's format.
///
/// The field names, values and layout mirror the RadPerf 2.0.1 summary
/// (`-s`) and JSON summary (`-j`) so that scripts parsing them keep working.
pub fn print_summary<W: Write>(
    stats: &Stats,
    elapsed: Duration,
    json: bool,
    out: &mut W,
) -> std::io::Result<()> {
    let secs = elapsed.as_secs();
    let millis = elapsed.subsec_millis();
    let elapsed_f = elapsed.as_secs_f64();
    let succeeded = stats.total_succeeded();
    let failed = stats.total_failed();
    let noreply = stats.timeouts;
    // The reference reports successful packets per second.
    let pps = if elapsed_f > 0.0 {
        succeeded as f64 / elapsed_f
    } else {
        0.0
    };

    if json {
        write!(out, "{{")?;
        writeln!(out, " \"total_sent\":\"{}\",", stats.requests_sent)?;
        writeln!(out, " \"total_retransmits\":\"{}\",", stats.retransmits)?;
        writeln!(out, " \"total_succeeded\":\"{}\",", succeeded)?;
        writeln!(out, " \"total_failed\":\"{}\",", failed)?;
        writeln!(out, " \"total_no_reply\":\"{}\",", noreply)?;
        writeln!(out, " \"total_time\":\"{}.{:03}\",", secs, millis)?;
        if pps < 10.0 {
            writeln!(out, " \"packets_per_second\":\"{:.1}\",", pps)?;
        } else {
            writeln!(out, " \"packets_per_second\":\"{:.0}\",", pps)?;
        }
        write!(out, " \"response_times\":[")?;
        for (i, count) in stats.decades.iter().enumerate() {
            if i > 0 {
                write!(out, ",")?;
            }
            write!(out, "\"{count}\"")?;
        }
        writeln!(out, "]}}")?;
        return Ok(());
    }

    writeln!(out, "\t     Total sent        :  {}", stats.requests_sent)?;
    writeln!(out, "\t     Total retransmits :  {}", stats.retransmits)?;
    writeln!(out, "\t     Total succeeded   :  {}", succeeded)?;
    writeln!(out, "\t     Total failed      :  {}", failed)?;
    writeln!(out, "\t     Total no reply    :  {}", noreply)?;
    writeln!(out, "\t     Total time (s)    :  {}.{:03}", secs, millis)?;
    if pps < 10.0 {
        writeln!(out, "\t     Packets/s         :  {:.1}", pps)?;
    } else {
        writeln!(out, "\t     Packets/s         :  {:.0}", pps)?;
    }
    writeln!(out, "\t     Response times:")?;
    for (i, name) in crate::stats::DECADE_NAMES.iter().enumerate() {
        writeln!(out, "\t\t< {:<9}: {}", name, stats.decades[i])?;
    }
    Ok(())
}

/// Print the program usage.
pub fn print_usage(program: &str) {
    let mut out = std::io::stdout();
    let _ = writeln!(
        out,
        "Usage: {program} [options] server[:port] <command> [<secret>]\n\
         \n\
         Commands: auth, acct, status, coa, disconnect, auto (or a code 1..255)\n\
         \n\
         Options:\n\
         \x20 -a type       authentication method: pap, chap, none\n\
         \x20 -A d,l        after Access-Accept, send accounting every d seconds for l seconds\n\
         \x20 -c count      send each input packet count times\n\
         \x20 -C attr[,..]  copy these attributes from Access-Accept to Accounting-Request\n\
         \x20 -d dir        dictionary directory\n\
         \x20 -D file       write per-packet num/time/delay to a file\n\
         \x20 -f file       read packets from file (repeatable; .csv selects CSV form)\n\
         \x20 -F            also update Framed-IP-Address\n\
         \x20 -j            print a JSON summary\n\
         \x20 -m mode       Message-Authenticator: auto (default), yes or no\n\
         \x20 -n num        pace new requests per second\n\
         \x20 -p num        maximum outstanding requests\n\
         \x20 -P            report per-second statistics\n\
         \x20 -q            quiet\n\
         \x20 -r retries    retransmit a request up to this many times\n\
         \x20 -R realm      append a realm to User-Name\n\
         \x20 -s            print a summary of results\n\
         \x20 -S file       read the shared secret from a file\n\
         \x20 -t timeout    retransmit timeout in seconds\n\
         \x20 -T file       template file added to every request\n\
         \x20 -u number     generate requests for this many users\n\
         \x20 -v            print version and exit\n\
         \x20 -x            increase debug output\n\
         \x20 -4 / -6       prefer IPv4 / IPv6 server address"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_stats() -> Stats {
        let mut stats = Stats::new();
        stats.requests_sent = 5;
        stats.access_accept = 5;
        // 4 responses below 1 ms, 1 below 10 ms.
        stats.decades = [0, 0, 4, 1, 0, 0, 0, 0];
        stats
    }

    #[test]
    fn summary_layout_matches_the_reference() {
        let mut out = Vec::new();
        print_summary(&sample_stats(), Duration::from_millis(8), false, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text,
            "\t     Total sent        :  5\n\
             \t     Total retransmits :  0\n\
             \t     Total succeeded   :  5\n\
             \t     Total failed      :  0\n\
             \t     Total no reply    :  0\n\
             \t     Total time (s)    :  0.008\n\
             \t     Packets/s         :  625\n\
             \t     Response times:\n\
             \t\t< 10 usec  : 0\n\
             \t\t< 100 usec : 0\n\
             \t\t< msec     : 4\n\
             \t\t< 10 msec  : 1\n\
             \t\t< 0.1s     : 0\n\
             \t\t< s        : 0\n\
             \t\t< 10s      : 0\n\
             \t\t< 100s     : 0\n"
        );
    }

    #[test]
    fn json_layout_matches_the_reference() {
        let mut out = Vec::new();
        print_summary(&sample_stats(), Duration::from_millis(8), true, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text,
            "{ \"total_sent\":\"5\",\n \"total_retransmits\":\"0\",\n \"total_succeeded\":\"5\",\n \"total_failed\":\"0\",\n \"total_no_reply\":\"0\",\n \"total_time\":\"0.008\",\n \"packets_per_second\":\"625\",\n \"response_times\":[\"0\",\"0\",\"4\",\"1\",\"0\",\"0\",\"0\",\"0\"]}\n"
        );
    }
}
