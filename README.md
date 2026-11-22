# WireGuard Mesh Syslog Receiver 📡

A zero-dependency, local-first Python TCP syslog receiver engineered for private WireGuard mesh networks, remote node survivability, IP allowlist enforcement, and Lynis LOGG-2154 compliance.

> *"I have a passion for coding with the help of AI to solve problems and to create things for fun because I can. To make that work at scale, AI agents need solid engineering foundations, deep documentation, and rigorous boundaries."*  
> — **Ethan (TWU LLC)**

[![CI](https://github.com/Ethan-da-Tech-Wizard/wireguard-mesh-syslog/actions/workflows/ci.yml/badge.svg)](https://github.com/Ethan-da-Tech-Wizard/wireguard-mesh-syslog/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10--3.13](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-brightgreen.svg)](https://docs.python.org/3/)
[![Rule 16 Compliant](https://img.shields.io/badge/Comment_Density-%E2%89%A525%25-gold.svg)](MAGI_BIBLE.md)
[![Magi Bible Verified](https://img.shields.io/badge/Magi_Bible-Verified-purple.svg)](MAGI_BIBLE.md)
[![Lynis: LOGG-2154](https://img.shields.io/badge/Compliance-Lynis%20LOGG--2154-success.svg)](https://cisofy.com/lynis/controls/LOGG-2154/)

---

## Architecture: Mesh-Isolated Log Ingestion & CWE-117 Sanitization

```mermaid
flowchart TD
    subgraph MeshNodes ["Fleet Mesh Nodes (WireGuard wg0)"]
        N1["Node Alpha (10.200.0.2)"]
        N2["Node Beta  (10.200.0.3)"]
        N3["Node Gamma (10.200.0.4)"]
    end

    subgraph Receiver ["Secure Log Receiver Daemon (mesh_log_receiver.py)"]
        BIND["TCP Listener Bound to 10.200.0.1:6514"]
        ALLOW["Strict CIDR & Peer Allowlist Filter"]
        FRAME["RFC 6587 Octet-Counting Framing Decoder"]
        SANITIZE["CWE-117 ANSI Escape Sanitization Sieve"]
        BIND --> ALLOW
        ALLOW --> FRAME
        FRAME --> SANITIZE
    end

    subgraph Storage ["Forensic Partitioned Logs"]
        LOG1["/var/log/remote-mesh/node-alpha/syslog.log"]
        LOG2["/var/log/remote-mesh/node-beta/syslog.log"]
        LOG3["/var/log/remote-mesh/node-gamma/syslog.log"]
        SANITIZE --> LOG1 & LOG2 & LOG3
    end

    N1 & N2 & N3 -->|Encrypted WireGuard Tunnel| BIND
```

---

## Visual Walkthrough & Diagnostics

<p align="center">
  <img src="assets/mesh_syslog_live.svg" alt="WireGuard Mesh Syslog Live Receiver Status" width="860">
</p>

```text
======================================================================
  📡 WIREGUARD MESH SECURE SYSLOG RECEIVER (Lynis LOGG-2154)
======================================================================
Bind Interface:    10.200.0.1:6514 (Encrypted WireGuard Mesh Interface wg0)
Peer Allowlist:    Strict CIDR 10.200.0.0/24 (Zero Public Internet Exposure)
Protocol Support:  RFC 5424 Structured & RFC 3164 Legacy (Octet-Counting Framing)
Sanitization:      CWE-117 Log Injection Defense (ANSI escape stripping active)
Receiver Status:   LISTENING & HEALTHY (Active Connections: 4)
Storage Policy:    /var/log/remote-mesh/%PEER%/%DATE%.log (Atomic Append)
======================================================================
```

<p align="center">
  <img src="docs/assets/mesh_syslog_receiver.svg" alt="WireGuard Mesh Syslog Ingestion" width="860">
</p>

<p align="center">
  <img src="docs/assets/mesh_syslog_telemetry.svg" alt="Mesh Syslog Sanitization & Verification" width="860">
</p>

---

## Quick Start & Usage

From the repository root:

```sh
# 1. Inspect daemon configuration and runtime parameters
python3 scripts/mesh_log_receiver.py --help
python3 scripts/mesh_log_receiver.py --status

# 2. Run receiver listening on configured WireGuard IP
python3 scripts/mesh_log_receiver.py --bind 10.200.0.1 --port 6514 --log-dir /var/log/remote-mesh

# 3. Test loopback ingestion and message framing
python3 -m unittest discover -s scripts -v
```

### Systemd Integration & Rsyslog Client

* **Client Forwarding Config:** [rsyslog-client.conf](rsyslog-client.conf) forwards system events over the encrypted WireGuard link.
* **Systemd Unit Files:** [systemd/mesh-syslog.service](systemd/) provisions hardened system-level process sandboxing (`ProtectSystem=strict`, `ProtectHome=read-only`).

---

## Engineering Standards & Magi Bible

All mesh syslog collectors, frame decoders, and stream filters strictly adhere to the **[Magi Bible: Engineering Foundations & Safety Standards for AI Coding](MAGI_BIBLE.md)** and **[MAGI_LOOK_HERE.md](MAGI_LOOK_HERE.md)**:
* **[MAGI_LOOK_HERE.md](MAGI_LOOK_HERE.md)**: Universal contributor & AI agent onboarding guide, visual walkthrough requirements, zero-PII validation rules.
* **[MAGI_BIBLE.md](MAGI_BIBLE.md)**: Core engineering foundations, multi-seat governance, and verification checklists.
* **Rule 16 Commenting Invariant ($\ge 25\%$):** Code contains comprehensive structural headers and inline rationale.
* **Fail-Closed Security Invariant:** Non-allowlisted IP connections are dropped immediately with zero TCP payload processing.
* **CWE-117 Protection:** Strips terminal escape codes, ANSI cursor controls, and illegal UTF-8 bytes before persisting logs to disk.

---

## License

Project source code is distributed under the **[MIT License](LICENSE)**.
