# WireGuard Mesh Remote Syslog Receiver

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.8+](https://img.shields.io/badge/Python-3.8%2B-brightgreen.svg)](https://www.python.org/)
[![Compliance: Lynis LOGG--2154](https://img.shields.io/badge/Compliance-Lynis%20LOGG--2154-success.svg)](https://cisofy.com/lynis/controls/LOGG-2154/)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Stdlib%20Only)-blueviolet.svg)](#architecture-overview)
[![RFC: 5424 / 3164](https://img.shields.io/badge/Standards-RFC%205424%20%7C%20RFC%203164-orange.svg)](#rfc-5424-vs-rfc-3164-syslog-protocols)

A hardened, zero-dependency, fail-closed remote syslog receiver built strictly for encrypted **WireGuard point-to-point mesh networks** (`10.200.0.0/24`).

Engineered to resolve edge node storage exhaustion (`ENOSPC`) on resource-constrained satellite nodes while satisfying **Lynis security benchmark `LOGG-2154`** without expanding network attack surface.

**Author:** Tech Wizard `<author@users.noreply.invalid>`  
**Organization:** TWU LLC  
**License:** MIT License (c) 2026 Tech Wizard, TWU LLC  

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [The Edge Node Survivability Problem](#the-edge-node-survivability-problem)
3. [RFC 5424 vs RFC 3164 Syslog Protocols](#rfc-5424-vs-rfc-3164-syslog-protocols)
4. [Transport Framing: Octet Counting vs Delimiter Framing](#transport-framing-octet-counting-vs-delimiter-framing)
5. [CIDR IP Allowlisting & Network Isolation](#cidr-ip-allowlisting--network-isolation)
6. [Hub Log Rotation & SIGHUP Architecture](#hub-log-rotation--sighup-architecture)
7. [Non-Root systemd Service Hardening & Sandboxing](#non-root-systemd-service-hardening--sandboxing)
8. [Lynis Compliance: Benchmark LOGG-2154](#lynis-compliance-benchmark-logg-2154)
9. [Repository Structure](#repository-structure)
10. [Quick Start & Installation](#quick-start--installation)
11. [Configuring Client Nodes (Edge Forwarding)](#configuring-client-nodes-edge-forwarding)
12. [Unit Test Suite](#unit-test-suite)
13. [License & Ownership](#license--ownership)

---

## Architecture Overview

In distributed and edge systems, satellite nodes (such as field laptops, remote developer machines, or edge controllers) frequently operate with constrained storage envelopes. When intensive tasks or runaway processes produce excessive logs, local storage in `/var/log` or systemd journal storage can rapidly trigger filesystem exhaustion (`ENOSPC`). This causes cascading service failures, kernel read-only panics, and the destruction of vital forensic logs.

Standard remote syslog aggregation typically involves exposing UDP or TCP port 514 across all network interfaces (`0.0.0.0`). Plain-text syslog exposes infrastructure to:
* **Eavesdropping:** Log entries containing internal hostnames, user accounts, and debug traces are broadcast unencrypted across the network.
* **Log Injection & Spoofing:** UDP 514 lacks source validation, allowing attackers to forge audit entries or flood log hosts.
* **Terminal Escape Sequence Injections:** Malicious payloads can inject ANSI control sequences to clear terminal screens or hijack administrative consoles when logs are inspected via `cat` or `tail`.

```
 +-------------------------------------------------------------------------------+
 |                        ENCRYPTED WIREGUARD OVERLAY                            |
 |                             (10.200.0.0/24)                                    |
 +-------------------------------------------------------------------------------+
                                         |
            TCP Stream                   |             Transport Check
   [Edge Node: 10.200.0.2]                |          [Hub Node: 10.200.0.1:6514]
   (rsyslog client daemon)               |           (mesh_log_receiver.py)
              |                          |                      |
              |=== WireGuard wg0 ========|=====================>|
              |    (ChaCha20-Poly1305)   |                      |
              |                          |               [verify_request()]
              |                          |               Is IP in KNOWN_PEERS?
              |                          |                  /        \
              |                          |            (YES)/          \(NO)
              |                          |                v            v
              |                          |         Accept Stream    Drop Socket
              |                          |                |
              |                          |        [sanitize_log_line()]
              |                          |        Strip ANSI sequences
              |                          |                |
              |                          |                v
              |                          |         Append to isolated
              |                          |     remote_logs/<peer>.log
```

---

## The Edge Node Survivability Problem

### The Storage Envelope Scenario
Consider a satellite edge node deployed on a laptop or embedded appliance with a 113 GB NVMe SSD running near capacity (~17 GB free disk capacity). When system daemons, compilers, or continuous services emit unexpected bursts of telemetry, local log files grow exponentially:
- `/var/log/messages`, `/var/log/syslog`, or systemd journal partitions fill rapidly.
- When disk usage reaches 100%, the Linux kernel returns `ENOSPC` (Error: No Space Left On Device).
- Critical system services fail, transactions are aborted, and the root filesystem may remount in a read-only state.
- Even worse, standard journal rotation policies begin discarding or corrupting the very log records required to diagnose why the system crashed.

### The Architectural Solution
1. **Real-Time Remote Offloading:** The edge node forwards every audit and system event across the WireGuard point-to-point overlay (`10.200.0.0/24`) to the hub receiver at `10.200.0.1:6514`.
2. **Bounded Local Disk Spooling:** The client rsyslog daemon is configured with a disk-assisted queue (`queue.maxDiskSpace="1g"`). If the WireGuard mesh is temporarily disconnected (e.g. edge laptop sleeping or roaming networks), logs are spooled up to a strict 1 GB ceiling, preventing `ENOSPC`.
3. **Resilient Reconnection:** Upon reconnecting to the mesh, buffered logs automatically flush to the central hub, guaranteeing zero log loss and zero edge disk exhaustion.

---

## RFC 5424 vs RFC 3164 Syslog Protocols

Syslog message payloads arrive formatted in either legacy BSD syntax or modern IETF structured format:

### 1. Priority (PRI) Calculation & Bitwise Decomposition
Every syslog message begins with a Priority code enclosed in angle brackets: `<PRI>`.
```
PRI = (Facility * 8) + Severity
```
To extract the facility and severity:
```python
facility = pri >> 3       # Integer division by 8
severity = pri & 0x07     # Modulo 8 (bitwise mask)
```

| Facility Code | Facility Name | Description |
| :---: | :--- | :--- |
| `0` | `kern` | Kernel messages |
| `1` | `user` | User-level messages |
| `3` | `daemon` | System daemons |
| `4` | `auth` | Security/authorization messages |
| `10` | `authpriv` | Security/authorization messages (private) |
| `13` | `audit` | Log audit |
| `16-23` | `local0` - `local7` | Locally defined facilities |

| Severity Code | Severity Name | Description |
| :---: | :--- | :--- |
| `0` | `emerg` | Emergency: system is unusable |
| `1` | `alert` | Action must be taken immediately |
| `2` | `crit` | Critical conditions |
| `3` | `err` | Error conditions |
| `4` | `warning` | Warning conditions |
| `5` | `notice` | Normal but significant condition |
| `6` | `info` | Informational messages |
| `7` | `debug` | Debug-level messages |

### 2. RFC 3164 (The BSD Syslog Protocol - Legacy)
```
<PRI>TIMESTAMP HOSTNAME TAG: MSG
```
*Example:* `<13>Nov  8 07:22:45 fedora sshd[1234]: Accepted publickey for ethan`
- Missing year and timezone information in the timestamp (`Nov  8 07:22:45`).
- Ambiguous tag boundaries and process identifiers.
- Maximum recommended message length of 1024 octets.

### 3. RFC 5424 (The Syslog Protocol - Modern IETF)
```
<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
```
*Example:* `<34>1 2026-11-08T07:22:45.123456Z fedora sshd 1234 ID47 [meta ip="10.200.0.2"] Key auth failed`
- Version 1 header.
- Full RFC 3339 timestamps with fractional seconds and explicit UTC timezone (`Z`).
- Formal structured data blocks `[SD-ID param="val"]` for standardized machine parsing.
- UTF-8 payload encoding without arbitrary 1024-byte limits.

---

## Transport Framing: Octet Counting vs Delimiter Framing

Stream-oriented protocols like TCP deliver a continuous byte stream without inherent packet boundaries. Framing standards define how receivers delineate individual log messages:

### 1. Non-Transparent Delimiter Framing (RFC 6587 Section 3.4.2)
Messages are delimited by a trailing linefeed (`\n`) or NUL byte.
- **The Delimiter-Splitting Vulnerability:** If a log message contains internal newlines (e.g. a Python traceback, Java stack trace, or multi-line JSON payload), the receiver interprets each newline as a distinct message boundary. This fractures the audit event across multiple disjoint log lines.

### 2. Octet Counting Framing (RFC 5425 Section 4.3.1 / RFC 6587 Section 3.4.1)
Each message begins with an ASCII decimal indicating its exact length in octets, followed by a space and the payload:
```
<MSGLEN> <MSG>
```
*Example:*
```text
56 <34>1 2026-11-08T07:22:45Z fedora app 1 ID - Multi-line
Payload with newline
```
- **Integrity Guarantee:** Because the receiver reads exactly `MSGLEN` bytes, payloads containing raw newlines, carriage returns, or binary characters remain unified as a single discrete audit record.

---

## CIDR IP Allowlisting & Network Isolation

Security is enforced through a multi-tier defense architecture:

### Tier 1: Kernel WireGuard Interface Isolation
- The receiver socket binds strictly to `10.200.0.1:6514`. It **never binds to `0.0.0.0`**.
- The Linux kernel network stack immediately drops any packet arriving on Ethernet (`eth0`), Wi-Fi (`wlan0`), or public WAN before reaching userspace.
- All inter-node traffic is encrypted with ChaCha20-Poly1305 and authenticated via Curve25519 elliptic-curve keys.

### Tier 2: CIDR Subnet Containment (`10.200.0.0/24`)
- Validates that client addresses reside within the private overlay subnet (`10.200.0.0/24`) or loopback (`127.0.0.1`).
- The `/24` subnet netmask `255.255.255.0` restricts valid peers to the range `10.200.0.1` through `10.200.0.254`.

### Tier 3: Transport-Layer IP Allowlisting (`verify_request()`)
- The server overrides `socketserver.ThreadingTCPServer.verify_request()`.
- During the TCP three-way handshake, the client IP address is evaluated against `KNOWN_MESH_PEERS` before allocating worker threads or reading buffers.
- Unauthenticated connections are dropped immediately at the socket level (fail-closed).

---

## Hub Log Rotation & SIGHUP Architecture

Central log repositories ingest continuous telemetry from multiple satellite nodes. Without systematic rotation, central disks face storage exhaustion.

### The File Descriptor Problem
When standard log rotators (`logrotate`) rotate active files (e.g. renaming `fedora.log` to `fedora.log.1`), the operating system preserves the existing file descriptor. If a long-running receiver daemon does not reopen its file handles, it continues writing into the renamed or compressed file.

### SIGHUP Atomic Reopening
1. `logrotate` moves the active log file and executes a postrotate command:
   ```bash
   kill -HUP $(pgrep -f mesh_log_receiver.py)
   ```
2. The receiver's SIGHUP signal handler flags an atomic descriptor refresh.
3. Subsequent write operations open fresh file handles in append mode, seamlessly routing new logs into the new `fedora.log` without dropping client TCP connections or restarting the daemon.

#### Sample Logrotate Configuration (`/etc/logrotate.d/wireguard-mesh-syslog`):
```text
/home/user/TWU_LLC/exports/wireguard-mesh-syslog/data/health/remote_logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        pkill -HUP -f mesh_log_receiver.py >/dev/null 2>&1 || true
    endscript
}
```

---

## Non-Root systemd Service Hardening & Sandboxing

The included service unit (`systemd/twu-mesh-log-receiver.service`) enforces strict non-root Linux kernel sandboxing:

| Directive | Security Objective |
| :--- | :--- |
| `WorkingDirectory=%h/...` | Runs under systemd user scope (`systemctl --user`), eliminating root privilege requirement. |
| `NoNewPrivileges=true` | Blocks privilege escalation via `setuid` / `setgid` binaries via `PR_SET_NO_NEW_PRIVS`. |
| `RestrictRealtime=true` | Prevents real-time CPU priority monopolization (`SCHED_FIFO`, `SCHED_RR`). |
| `LockPersonality=true` | Locks execution domain to native Linux personality, preventing personality alteration attacks. |
| `SystemCallArchitectures=native` | Denies execution of foreign or legacy 32-bit system calls, shrinking kernel attack surface. |
| `UMask=0077` | Restricts log file creation permissions strictly to `0600` (owner read/write only). |
| `CPUQuota=25%` | Caps processor consumption under heavy syslog bursts. |
| `MemoryMax=512M` | Enforces hard cgroup v2 memory ceiling against denial-of-service memory pressure. |
| `ExecReload=/bin/kill -HUP $MAINPID` | Dispatches SIGHUP on reload to trigger atomic log file rotation. |

---

## Lynis Compliance: Benchmark LOGG-2154

During security audits using [Lynis](https://cisofy.com/lynis/) (CIS-compliant auditing engine), standard systems frequently flag:

> **Suggestion:** Configure a remote log host to send syslog messages to (`LOGG-2154`).

Deploying generic syslog daemons often lowers the overall security posture by introducing unauthenticated listening ports on public interfaces. This project directly resolves `LOGG-2154` by establishing an authenticated, encrypted, peer-restricted remote logging endpoint over WireGuard.

---

## Repository Structure

```
wireguard-mesh-syslog/
├── scripts/
│   ├── mesh_log_receiver.py       # Core remote syslog receiver daemon
│   └── test_mesh_log_receiver.py  # Unit test suite (zero external dependencies)
├── systemd/
│   ├── twu-mesh-log-receiver.service       # Hardened systemd service unit
│   └── user__twu-mesh-log-receiver.service # User-level systemd configuration
├── docs/
│   └── PLATFORM_SECURITY_WHITEPAPER.md    # Complete platform security whitepaper
├── rsyslog-client.conf           # Client rsyslog configuration with disk spooling
├── README.md                      # Architectural and operational documentation
├── LICENSE                        # MIT License
└── .gitignore                     # Git artifact exclusions
```

---

## Quick Start & Installation

### Prerequisites
* Linux or Unix host with Python 3.8 or higher.
* Active WireGuard network interface (e.g. `wg0`) assigned `10.200.0.1` (or custom overlay IP).

### 1. Inspect Status
Verify the configuration, subnet, and registered mesh peers:
```bash
python3 scripts/mesh_log_receiver.py --status
```
Output:
```text
=== WireGuard Mesh Syslog Receiver Status ===
Configured Bind Target : 10.200.0.1:6514
WireGuard Mesh CIDR    : 10.200.0.0/24
Log Storage Directory  : /path/to/data/health/remote_logs
Allowed Mesh Peers (4) :
  - 10.200.0.1       -> host-1
  - 10.200.0.2       -> fedora
  - 10.200.0.3       -> host-2
  - 127.0.0.1       -> localhost
```

### 2. Run the Unit Test Suite
Execute the zero-dependency test suite:
```bash
python3 -m unittest discover -s scripts
```

### 3. Run the Receiver in Foreground
```bash
python3 scripts/mesh_log_receiver.py --bind 10.200.0.1 --port 6514
```

### 4. Deploy as a Hardened systemd Service
Deploy as a systemd user service:
```bash
mkdir -p ~/.config/systemd/user/
cp systemd/twu-mesh-log-receiver.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now twu-mesh-log-receiver.service
```

Check service status and journal output:
```bash
systemctl --user status twu-mesh-log-receiver.service
```

---

## Configuring Client Nodes (Edge Forwarding)

On each edge or satellite node (e.g., Fedora, Debian, Ubuntu):

1. Copy the sample rsyslog client configuration:
   ```bash
   sudo cp rsyslog-client.conf /etc/rsyslog.d/50-mesh-syslog.conf
   ```

2. Verify mesh connectivity:
   ```bash
   ping -c 2 10.200.0.1
   ```

3. Restart rsyslog:
   ```bash
   sudo systemctl restart rsyslog
   ```

4. Emit a test audit log event:
   ```bash
   logger -t audit-test "WireGuard mesh logging validation from $(hostname)"
   ```

5. Verify receipt on the hub node:
   ```bash
   tail -n 10 data/health/remote_logs/fedora.log
   ```
   Example output:
   ```text
   2026-11-08T07:22:45Z [fedora] audit-test: WireGuard mesh logging validation from fedora
   ```

---

## Unit Test Suite

The test suite (`scripts/test_mesh_log_receiver.py`) validates all operational and security boundaries:

```bash
python3 -m unittest scripts/test_mesh_log_receiver.py
```

Test coverage includes:
- `test_sanitize_log_line`: ANSI terminal injection and null-byte stripping.
- `test_verify_request_allowed_and_rejected`: Transport-layer IP allowlist enforcement.
- `test_cidr_mesh_subnet_validation`: Mathematical validation of `10.200.0.0/24` subnet boundaries.
- `test_parse_syslog_rfc5424`: RFC 5424 PRI math, RFC 3339 timestamps, and structured data extraction.
- `test_parse_syslog_rfc3164`: RFC 3164 BSD legacy format parsing.
- `test_live_loopback_log_ingest`: Live end-to-end TCP loopback transmission and atomic disk write.
- `test_live_octet_counting_framing_ingest`: RFC 6587 Section 3.4.1 octet counting ingestion.

---

## License & Ownership

**Author:** Tech Wizard `<author@users.noreply.invalid>`  
**Organization:** TWU LLC  
**License:** MIT License (c) 2026 Tech Wizard, TWU LLC. See [LICENSE](LICENSE) for full legal text.
