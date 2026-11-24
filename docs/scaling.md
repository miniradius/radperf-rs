# Client scaling

## Sandbox measurements

The Linux arm64 radperf-rs 0.1.0 candidate (`94b911e`) ran directly in the
sandbox on loopback. One, two, or four client processes were pinned to separate
CPUs. The total parallelism stayed at 64, split as `-p 64`, `-p 32`, or
`-p 16` per process. Each row summarizes five runs of 200,000 PAP requests
using quiet mode, `-m no`, and per-response recording with `-D`. A minimal
UDP responder signed each Access-Accept. Responders ran on CPUs separate from
the clients.

Throughput includes client startup and shutdown. The table reports medians
across runs. CPU is the utilization of the busiest process of each kind per
run, expressed as a percentage of one CPU.

| Responders | Client processes | Replies/s | p95 (µs) | Client CPU | Responder CPU |
| --- | ---: | ---: | ---: | ---: | ---: |
| One per client | 1 | 603,546 | 93 | 99.9% | 88.5% |
| One per client | 2 | 1,072,417 | 54 | 98.7% | 86.9% |
| One per client | 4 | 1,907,332 | 36 | 97.6% | 84.5% |
| One shared | 1 | 620,188 | 90 | 99.4% | 88.0% |
| One shared | 2 | 644,225 | 126 | 61.7% | 97.1% |
| One shared | 4 | 611,343 | 131 | 33.7% | 97.5% |

Each responder topology completed three million requests without losses or
retransmissions.

## Interpretation

Four client–responder pairs achieved 3.16× the throughput of one pair. The
single client used essentially all of its assigned CPU. With a shared
responder, adding clients raised the responder's utilization to about 97% and
throughput stayed roughly flat. The measured gain applies to independent
processes with additional responder capacity. A threaded client still needs
its own comparison.

## Follow-up

1. Repeat the one-, two-, and four-process runs against an independent RADIUS
   server with verified spare capacity. Keep total parallelism fixed and record
   reply throughput, p95 latency, losses, retransmissions, and CPU utilization
   on both sides. Compare runs with and without `-D`.
2. If extra client CPUs improve throughput, prototype one `mio` loop per
   worker with its own UDP sockets. Preserve the run-wide limits for `-p`
   and `-n`, and merge worker statistics after the run. Compare the prototype
   with the same number of independent processes.
3. Use profiling to decide whether Linux batching with `sendmmsg` and
   `recvmmsg` is worth testing. Consider `SO_REUSEPORT` if a shared local
   port becomes a requirement.
