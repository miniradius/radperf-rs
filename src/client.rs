//! The send/receive engine: a single-threaded `mio` (epoll/kqueue) event loop.
//!
//! Design notes for throughput:
//! * Outstanding requests are matched in O(1) via a per-socket 256-entry array
//!   indexed by the RADIUS identifier (no hash map on the hot path).
//! * Each slot owns a reusable packet buffer, so steady-state sending performs
//!   no allocation: the template is written into the slot buffer in place.
//! * Timeouts live in a binary min-heap keyed by deadline; stale entries are
//!   discarded on pop using a generation counter.
//! * Latency is recorded into a fixed-size histogram (O(1), no allocation).

use crate::accounting::{self, AcctConfig};
use crate::crypto;
use crate::packet::Packet;
use crate::request::Template;
use crate::rng::Rng;
use crate::stats::Stats;
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::io::{self, BufWriter, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const MAX_SLOTS: usize = 256;
const RECV_BUF: usize = 65_536;

/// Runtime configuration for one run.
#[derive(Clone)]
pub struct ClientConfig {
    pub server: SocketAddr,
    pub secret: Vec<u8>,
    pub parallel: usize,
    pub rate: u64,
    pub retries: u32,
    pub timeout: Duration,
    pub quiet: bool,
    pub debug: u32,
    pub collect_stats: bool,
    pub json_summary: bool,
    pub print_summary: bool,
    pub delays: Option<PathBuf>,
    /// Emit a per-second progress line during the run (`-P`).
    pub persec: bool,
    /// When set, accepted sessions trigger the accounting flow.
    pub accounting: Option<AcctConfig>,
    /// Skip the authentication phase and run the accounting flow directly
    /// (`-a none`).
    pub accounting_direct: bool,
    /// Destination for Accounting-Requests (usually the server's port 1813).
    pub acct_server: Option<SocketAddr>,
    /// Attribute types copied from the Access-Accept into accounting packets.
    pub acct_copy_types: Vec<u8>,
    /// Per-template base attributes copied from the Access-Request.
    pub acct_bases: Vec<Vec<u8>>,
}

/// A request in flight.
struct Slot {
    /// Reusable packet buffer (kept across sends to avoid allocation).
    buf: Vec<u8>,
    len: usize,
    occupied: bool,
    sent: Instant,
    sent_offset: f64,
    deadline: Instant,
    retries: u32,
    authenticator: [u8; 16],
    number: u64,
    template: u32,
    generation: u64,
    accounting_session: Option<usize>,
}

impl Slot {
    fn new() -> Slot {
        Slot {
            buf: Vec::with_capacity(512),
            len: 0,
            occupied: false,
            sent: Instant::now(),
            sent_offset: 0.0,
            deadline: Instant::now(),
            retries: 0,
            authenticator: [0u8; 16],
            number: 0,
            template: 0,
            generation: 0,
            accounting_session: None,
        }
    }
}

struct SocketState {
    sock: UdpSocket,
    slots: Vec<Slot>,
    in_flight: usize,
    next_id: u8,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TimeEntry {
    deadline: Instant,
    socket: usize,
    id: u8,
    generation: u64,
}

/// The engine.
pub struct Client {
    config: ClientConfig,
    poll: Poll,
    sockets: Vec<SocketState>,
    templates: Vec<Template>,
    jobs: Vec<u32>,
    next_job: usize,
    next_socket: usize,
    in_flight: usize,
    heap: BinaryHeap<Reverse<TimeEntry>>,
    rng: Rng,
    stats: Stats,
    start: Instant,
    last_send: Option<Instant>,
    next_send: Instant,
    generation: u64,
    packet_number: u64,
    delays: Option<BufWriter<std::fs::File>>,
    accepted: Vec<Accepted>,
    accounting_phase: bool,
    accounting_completed: Vec<usize>,
    next_report: Option<Instant>,
    last_sent: u64,
    last_received: u64,
}

/// A session that was accepted and needs accounting packets.
struct Accepted {
    template: u32,
    copied: Vec<(u8, Vec<u8>)>,
    session_timeout: Option<u32>,
}

struct AccountingSession {
    accepted: Accepted,
    id: String,
    index: usize,
    stop: Option<Instant>,
    next: Option<Instant>,
}

impl Client {
    /// Create an engine. `jobs` is the sequence of template indices to send.
    pub fn new(
        config: ClientConfig,
        templates: Vec<Template>,
        jobs: Vec<u32>,
    ) -> io::Result<Client> {
        let (poll, sockets) = open_sockets(config.server, config.parallel)?;
        let delays = match &config.delays {
            Some(path) => Some(BufWriter::new(std::fs::File::create(path)?)),
            None => None,
        };
        let persec = config.persec;
        Ok(Client {
            config,
            poll,
            sockets,
            templates,
            jobs,
            next_job: 0,
            next_socket: 0,
            in_flight: 0,
            heap: BinaryHeap::new(),
            rng: Rng::from_os(),
            stats: Stats::new(),
            start: Instant::now(),
            last_send: None,
            next_send: Instant::now(),
            generation: 0,
            packet_number: 0,
            delays,
            accepted: Vec::new(),
            accounting_phase: false,
            accounting_completed: Vec::new(),
            next_report: if persec {
                Some(Instant::now() + Duration::from_secs(1))
            } else {
                None
            },
            last_sent: 0,
            last_received: 0,
        })
    }

    /// Run to completion and return the collected statistics.
    pub fn run(&mut self) -> io::Result<Stats> {
        let run_result = self.run_requests().and_then(|()| self.run_accounting());
        let flush_result = self.delays.take().map_or(Ok(()), |mut w| w.flush());
        run_result?;
        flush_result?;
        Ok(self.stats.clone())
    }

    /// Statistics collected so far, including after an interrupted or failed run.
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    fn run_requests(&mut self) -> io::Result<()> {
        let mut events = Events::with_capacity(1024);
        let mut buf = vec![0u8; RECV_BUF];
        while !crate::signals::interrupted() {
            while self.can_send()
                && self.next_job < self.jobs.len()
                && !crate::signals::interrupted()
            {
                let template = self.jobs[self.next_job];
                if !self.send_request(template, None)? {
                    break;
                }
                self.next_job += 1;
            }
            if (self.next_job >= self.jobs.len() && self.in_flight == 0)
                || crate::signals::interrupted()
            {
                break;
            }
            let next_job = (self.next_job < self.jobs.len()).then_some(self.next_send);
            let timeout = self.next_timeout(next_job);
            self.poll_requests(&mut events, &mut buf, timeout)?;
        }
        Ok(())
    }

    fn can_send(&self) -> bool {
        self.in_flight < self.config.parallel
            && (self.config.rate == 0 || Instant::now() >= self.next_send)
    }

    fn poll_requests(
        &mut self,
        events: &mut Events,
        buf: &mut [u8],
        timeout: Duration,
    ) -> io::Result<()> {
        if let Err(e) = self.poll.poll(events, Some(timeout)) {
            return if e.kind() == io::ErrorKind::Interrupted {
                Ok(())
            } else {
                Err(e)
            };
        }
        for event in events.iter() {
            if event.is_readable() || event.is_error() {
                self.drain_socket(event.token().0, buf)?;
            }
        }
        self.process_timeouts()?;
        self.maybe_report();
        Ok(())
    }

    /// Choose a socket with a free identifier, build the packet and send it.
    fn send_request(
        &mut self,
        template_idx: u32,
        accounting: Option<(&AccountingSession, u8)>,
    ) -> io::Result<bool> {
        // Round-robin over sockets for a free slot.
        let n = self.sockets.len();
        let mut chosen = None;
        for k in 0..n {
            let idx = (self.next_socket + k) % n;
            if self.sockets[idx].in_flight < MAX_SLOTS {
                chosen = Some(idx);
                break;
            }
        }
        let Some(sock_idx) = chosen else {
            return Ok(false);
        };
        self.next_socket = (sock_idx + 1) % n;

        // Find a free identifier.
        let sock = &mut self.sockets[sock_idx];
        let mut id = sock.next_id;
        for _ in 0..MAX_SLOTS {
            if !sock.slots[id as usize].occupied {
                break;
            }
            id = id.wrapping_add(1);
        }
        sock.next_id = id.wrapping_add(1);
        if sock.slots[id as usize].occupied {
            return Ok(false); // no free slot after all
        }

        let now = Instant::now();
        self.generation += 1;
        let generation = self.generation;
        self.packet_number += 1;
        let number = self.packet_number;
        let sent_offset = now.duration_since(self.start).as_secs_f64();

        let slot = &mut sock.slots[id as usize];
        let len = if let Some((session, status)) = accounting {
            let base = self.config.acct_bases.get(template_idx as usize);
            accounting::build_accounting(
                &mut slot.buf,
                id,
                &self.config.secret,
                base.map_or(&[], Vec::as_slice),
                status,
                session.id.as_bytes(),
                session.index as u32 + 1,
                &session.accepted.copied,
            )
        } else {
            self.templates[template_idx as usize].build_into(
                id,
                &self.config.secret,
                &mut self.rng,
                &mut slot.buf,
            )
        };
        slot.len = len;
        slot.sent = now;
        slot.sent_offset = sent_offset;
        slot.deadline = now + self.config.timeout;
        slot.retries = 0;
        slot.number = number;
        slot.template = template_idx;
        slot.generation = generation;
        slot.accounting_session = accounting.map(|(session, _)| session.index);
        slot.authenticator.copy_from_slice(&slot.buf[4..20]);

        let n = sock
            .sock
            .send(&slot.buf[..len])
            .map_err(|err| udp_error("send", self.config.server, err))?;
        slot.occupied = true;
        self.stats.requests_sent += 1;
        self.stats.bytes_sent += n as u64;
        if let Some(prev) = self.last_send {
            self.stats
                .send_delay
                .record(now.duration_since(prev).as_micros() as u64);
        }
        self.last_send = Some(now);
        if self.config.rate > 0 {
            // Advance on a fixed grid so a burst makes up for the
            // millisecond granularity of the poll timeout. Only
            // resynchronize when we fell far behind (e.g. blocked by
            // the parallelism limit), to avoid a large catch-up burst.
            let interval = Duration::from_nanos(1_000_000_000 / self.config.rate.max(1));
            self.next_send += interval;
            if now.saturating_duration_since(self.next_send) > Duration::from_millis(5) {
                self.next_send = now;
            }
        }
        sock.in_flight += 1;
        self.in_flight += 1;
        self.heap.push(Reverse(TimeEntry {
            deadline: slot.deadline,
            socket: sock_idx,
            id,
            generation,
        }));
        Ok(true)
    }

    /// Drain all currently readable datagrams on one socket.
    fn drain_socket(&mut self, socket: usize, buf: &mut [u8]) -> io::Result<()> {
        loop {
            let n = {
                let sock = &self.sockets[socket];
                match sock.sock.recv(buf) {
                    Ok(n) => n,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(udp_error("receive", self.config.server, e)),
                }
            };
            self.handle_packet(socket, &buf[..n]);
        }
    }

    fn handle_packet(&mut self, socket: usize, bytes: &[u8]) {
        self.stats.bytes_received += bytes.len() as u64;
        let packet = match Packet::decode(bytes) {
            Ok(p) => p,
            Err(_) => {
                self.stats.malformed += 1;
                return;
            }
        };
        let now = Instant::now();
        let sock = &mut self.sockets[socket];
        let slot = &mut sock.slots[packet.id as usize];
        if !slot.occupied {
            self.stats.unmatched += 1;
            return;
        }
        if !crypto::verify_response_authenticator(&packet, &slot.authenticator, &self.config.secret)
        {
            self.stats.unmatched += 1;
            return;
        }
        let rtt = now.duration_since(slot.sent);
        self.stats.rtt.record(rtt.as_micros() as u64);
        self.stats.record_decade(rtt.as_micros() as u64);
        self.stats.responses_received += 1;
        self.stats.record_response_code(packet.code);
        if !self.accounting_phase
            && self.config.accounting.is_some()
            && packet.code == crate::packet::ACCESS_ACCEPT
        {
            let template = slot.template;
            let copied = accounting::copy_from_packet(&packet, &self.config.acct_copy_types);
            let session_timeout =
                accounting::read_uint_attribute(&packet, accounting::ATTR_SESSION_TIMEOUT);
            self.accepted.push(Accepted {
                template,
                copied,
                session_timeout,
            });
        }
        if !self.accounting_phase && !self.config.quiet {
            // The reference logs every response at the default verbosity.
            eprintln!(
                "Received response ID {}, code {}, length = {}",
                packet.id,
                packet.code,
                bytes.len()
            );
        }
        if let Some(w) = self.delays.as_mut() {
            // Relative send time and elapsed time since the first send.
            let so_sec = slot.sent_offset as u64;
            let so_usec = ((slot.sent_offset - so_sec as f64) * 1_000_000.0) as u32;
            let _ = writeln!(
                w,
                "{} {}.{:06} {}.{:06}",
                slot.number,
                so_sec,
                so_usec,
                rtt.as_secs(),
                rtt.subsec_micros()
            );
        }
        slot.occupied = false;
        self.accounting_completed.extend(slot.accounting_session);
        sock.in_flight -= 1;
        self.in_flight -= 1;
    }

    fn process_timeouts(&mut self) -> io::Result<()> {
        let now = Instant::now();
        while let Some(Reverse(entry)) = self.heap.peek().copied() {
            if entry.deadline > now {
                break;
            }
            self.heap.pop();
            let state = &mut self.sockets[entry.socket];
            let SocketState {
                sock,
                slots,
                in_flight,
                ..
            } = state;
            let slot = &mut slots[entry.id as usize];
            if !slot.occupied || slot.generation != entry.generation {
                continue;
            }
            if slot.retries < self.config.retries {
                let sent = sock
                    .send(&slot.buf[..slot.len])
                    .map_err(|err| udp_error("retransmit", self.config.server, err))?;
                self.stats.bytes_sent += sent as u64;
                slot.retries += 1;
                slot.deadline = now + self.config.timeout;
                let deadline = slot.deadline;
                self.stats.retransmits += 1;
                self.heap.push(Reverse(TimeEntry {
                    deadline,
                    socket: entry.socket,
                    id: entry.id,
                    generation: entry.generation,
                }));
            } else {
                self.stats.timeouts += 1;
                slot.occupied = false;
                self.accounting_completed.extend(slot.accounting_session);
                *in_flight -= 1;
                self.in_flight -= 1;
            }
        }
        Ok(())
    }

    /// Schedule accounting sessions independently after the authentication phase.
    fn run_accounting(&mut self) -> io::Result<()> {
        let (Some(config), Some(server)) =
            (self.config.accounting.clone(), self.config.acct_server)
        else {
            return Ok(());
        };
        if crate::signals::interrupted() {
            return Ok(());
        }
        if config.delay.is_zero() || Instant::now().checked_add(config.lifetime).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "accounting requires a positive delay and a representable lifetime",
            ));
        }

        let accepted = if self.config.accounting_direct {
            (0..self.templates.len() as u32)
                .map(|template| Accepted {
                    template,
                    copied: Vec::new(),
                    session_timeout: None,
                })
                .collect()
        } else {
            std::mem::take(&mut self.accepted)
        };
        if accepted.is_empty() {
            return Ok(());
        }

        (self.poll, self.sockets) = open_sockets(server, self.config.parallel)?;
        self.config.server = server;
        self.accounting_phase = true;
        self.next_socket = 0;
        self.heap.clear();
        self.last_send = None;
        let start = Instant::now();
        self.next_send = start;

        let mut sessions: Vec<_> = accepted
            .into_iter()
            .enumerate()
            .map(|(i, accepted)| AccountingSession {
                accepted,
                id: format!("{:016x}", self.rng.next_u64()),
                index: i,
                stop: None,
                next: None,
            })
            .collect();
        let mut schedule: BinaryHeap<_> =
            (0..sessions.len()).map(|i| Reverse((start, i))).collect();
        let mut events = Events::with_capacity(1024);
        let mut buf = vec![0u8; RECV_BUF];

        while !crate::signals::interrupted() {
            while self.can_send() && !crate::signals::interrupted() {
                let Some(Reverse((deadline, i))) = schedule.peek().copied() else {
                    break;
                };
                let now = Instant::now();
                if deadline > now {
                    break;
                }
                let session = &mut sessions[i];
                let status = match session.stop {
                    None => accounting::STATUS_START,
                    Some(stop) if now >= stop => accounting::STATUS_STOP,
                    Some(_) => accounting::STATUS_INTERIM,
                };
                if !self.send_request(session.accepted.template, Some((session, status)))? {
                    break;
                }
                schedule.pop();

                let next = match status {
                    accounting::STATUS_START => {
                        let lifetime = session
                            .accepted
                            .session_timeout
                            .map_or(config.lifetime, |s| {
                                Duration::from_secs(s.into()).min(config.lifetime)
                            });
                        let stop = now.checked_add(lifetime).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "accounting lifetime is too large",
                            )
                        })?;
                        session.stop = Some(stop);
                        now.checked_add(config.delay).unwrap_or(stop).min(stop)
                    }
                    accounting::STATUS_STOP => continue,
                    _ => {
                        let stop = session.stop.unwrap();
                        deadline
                            .checked_add(config.delay)
                            .unwrap_or(stop)
                            .max(now)
                            .min(stop)
                    }
                };
                session.next = Some(next);
            }

            if (schedule.is_empty() && self.in_flight == 0) || crate::signals::interrupted() {
                break;
            }
            let next_send = schedule.peek().map(|Reverse((deadline, _))| *deadline);
            let timeout = self.next_timeout(next_send).min(Duration::from_millis(100));
            self.poll_requests(&mut events, &mut buf, timeout)?;
            // Keep a session's phases ordered while other sessions can send
            // during its response wait and retransmissions.
            for i in self.accounting_completed.drain(..) {
                if let Some(next) = sessions[i].next.take() {
                    schedule.push(Reverse((next, i)));
                }
            }
        }
        Ok(())
    }

    /// Emit a per-second progress line when `-P` is enabled.
    fn maybe_report(&mut self) {
        let Some(next) = self.next_report else {
            return;
        };
        let now = Instant::now();
        if now < next {
            return;
        }
        let elapsed = now.duration_since(self.start).as_secs_f64();
        let d_sent = self.stats.requests_sent - self.last_sent;
        let d_recv = self.stats.responses_received - self.last_received;
        let loss = if d_sent > 0 {
            100.0 * (1.0 - d_recv as f64 / d_sent as f64)
        } else {
            0.0
        };
        eprintln!(
            "[{elapsed:6.1}s] sent {:>10} recv {:>10} loss {:>6.2}% rate {:>10}/s",
            d_sent, d_recv, loss, d_sent
        );
        self.last_sent = self.stats.requests_sent;
        self.last_received = self.stats.responses_received;
        self.next_report = Some(next + Duration::from_secs(1));
    }

    fn next_timeout(&self, next_job: Option<Instant>) -> Duration {
        let next_send = next_job
            .filter(|_| self.in_flight < self.config.parallel)
            .map(|due| due.max(self.next_send));
        [
            self.next_report,
            self.heap.peek().map(|entry| entry.0.deadline),
            next_send,
        ]
        .into_iter()
        .flatten()
        .min()
        .map_or(Duration::from_millis(50), |due| {
            due.saturating_duration_since(Instant::now())
        })
    }
}

fn open_sockets(server: SocketAddr, parallel: usize) -> io::Result<(Poll, Vec<SocketState>)> {
    let socket_count = parallel.div_ceil(MAX_SLOTS).max(1);
    let poll = Poll::new()?;
    let mut sockets = Vec::with_capacity(socket_count);
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    for i in 0..socket_count {
        let mut sock = UdpSocket::bind(bind)?;
        sock.connect(server)?;
        poll.registry()
            .register(&mut sock, Token(i), Interest::READABLE)?;
        let slots = (0..MAX_SLOTS).map(|_| Slot::new()).collect();
        sockets.push(SocketState {
            sock,
            slots,
            in_flight: 0,
            next_id: 0,
        });
    }
    Ok((poll, sockets))
}

fn udp_error(operation: &str, server: SocketAddr, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("UDP {operation} ({server}): {error}"))
}
