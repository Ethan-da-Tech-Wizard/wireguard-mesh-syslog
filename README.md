# WireGuard Mesh Remote Syslog Receiver

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.8+](https://img.shields.io/badge/Python-3.8%2B-brightgreen.svg)](https://www.python.org/)
[![Compliance: Lynis LOGG--2154](https://img.shields.io/badge/Compliance-Lynis%20LOGG--2154-success.svg)](https://cisofy.com/lynis/controls/LOGG-2154/)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Stdlib%20Only)-blueviolet.svg)](#architecture)

A hardened, zero-dependency, fail-closed remote syslog receiver built strictly for encrypted **WireGuard point-to-point mesh networks** (`10.200.0.0/24`).

Engineered to resolve edge node storage exhaustion (`ENOSPC`) on resource-constrained satellite nodes while satisfying **Lynis security benchmark `LOGG-2154`** without expanding network attack surface.

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

## Defense-in-Depth Security Model

The system implements a three-tier defense-in-depth model:

### 1. Interface-Level Confinement (Physical Attack Surface = 0)
* **Exclusive Socket Binding:** The receiver binds strictly to `10.200.0.1:6514` (the WireGuard interface IP). It **never binds to `0.0.0.0`**.
* **Unreachable via LAN/WAN:** The kernel network stack automatically rejects any packet arriving on Ethernet (`eth0`), Wi-Fi (`wlan0`), or public IP interfaces before it reaches the Python runtime.
* **Cryptographic Tunneling:** All inter-node traffic is encrypted with ChaCha20-Poly1305 and authenticated via Curve25519 elliptic-curve keys.

### 2. Transport-Layer IP Allowlisting (`verify_request`)
* The receiver overrides `socketserver.ThreadingTCPServer.verify_request()`.
* When a TCP connection is established, the client IP address is checked against `KNOWN_MESH_PEERS` before allocating worker threads or reading user space bytes.
* Unauthenticated connections are dropped immediately at the socket level (fail-closed).

### 3. Log Stream Sanitization (Anti-Terminal Injection)
* Logs are sanitized via `sanitize_log_line()` before writing to disk.
* Strips ANSI escape codes (`\x1b[...]`), cursor movement sequences, screen-clearing codes, null bytes (`\x00`), and non-printable control characters.
* Preserves tabs (`\t`) and printable ASCII characters (ordinals 32 to 126), preventing terminal injection exploits when operators inspect logs with `tail -f`, `cat`, or `less`.

---

## Lynis Compliance: Benchmark `LOGG-2154`

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
└── .gitignore                     # Git artifact exclusions
```

---

## Quick Start & Installation

### Prerequisites
* Linux or Unix host with Python 3.8 or higher.
* Active WireGuard network interface (e.g. `wg0`) assigned `10.200.0.1` (or custom overlay IP).

### 1. Inspect Status
Verify the configuration and registered mesh peers:
```bash
python3 scripts/mesh_log_receiver.py --status
```
Output:
```text
=== WireGuard Mesh Syslog Receiver Status ===
Configured Bind Target : 10.200.0.1:6514
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

## systemd Confinement & Hardening Profile

The included systemd unit (`systemd/twu-mesh-log-receiver.service`) enforces strict kernel-level sandboxing:

| Directive | Security Objective |
| :--- | :--- |
| `NoNewPrivileges=true` | Blocks privilege escalation via `setuid` / `setgid` binaries. |
| `RestrictRealtime=true` | Prevents real-time CPU priority monopolization. |
| `LockPersonality=true` | Locks execution domain to native Linux personality. |
| `SystemCallArchitectures=native` | Denies execution of foreign or legacy 32-bit system calls. |
| `UMask=0077` | Restricts log file creation permissions strictly to `0600` (owner read/write only). |
| `CPUQuota=25%` | Caps processor consumption under heavy syslog bursts. |
| `MemoryMax=512M` | Enforces hard cgroup v2 memory cap against denial-of-service memory pressure. |

---

## Security Whitepaper

For the comprehensive technical specification covering distributed platform architecture, cgroup v2 resource isolation, Linux namespace sandboxing, and multi-engine malware scanning pipelines, see:
* [`docs/PLATFORM_SECURITY_WHITEPAPER.md`](docs/PLATFORM_SECURITY_WHITEPAPER.md)

---

## License

This project is licensed under the MIT License.
