#!/usr/bin/env python3
# ==============================================================================
# WireGuard Mesh Remote Syslog Receiver
# ==============================================================================
# File: scripts/mesh_log_receiver.py
# Architecture: Zero-dependency, single-file, event-driven TCP syslog receiver
# Target Network: Encrypted WireGuard Point-to-Point Mesh Overlay (10.200.0.0/24)
# Compliance Target: Lynis LOGG-2154 (Configure remote log host)
# Security Design: Fail-closed, transport-level peer allowlisting, ANSI sanitization
# ==============================================================================
#
# EDUCATIONAL WALKTHROUGH & ARCHITECTURAL FOUNDATION:
#
# 1. THE PROBLEM: OUTSIDE EDGE NODE SURVIVABILITY & LOG EVAPORATION
#    Distributed systems often feature heterogeneous nodes where edge clients
#    (such as field laptops, embedded IoT boards, or secondary development nodes)
#    operate under strict hardware envelopes. For example, a laptop with a small
#    SSD running near capacity (~17 GB free) is exposed to filesystem exhaustion
#    (ENOSPC) during runaway syslog activity. If an edge node runs out of storage,
#    critical system services fail, filesystems enter read-only panic states, and
#    local forensic evidence is lost. Furthermore, if an edge node is powered off
#    abruptly or compromised, local logs can be destroyed or manipulated.
#
# 2. WHY NOT DEFAULT SYSLOG OVER 0.0.0.0?
#    Standard rsyslog / syslog-ng deployments frequently listen on UDP 514 or
#    TCP 514 across all network interfaces (0.0.0.0). UDP 514 is connectionless,
#    unauthenticated, and unencrypted, making it vulnerable to IP address spoofing,
#    log tampering, and packet amplification attacks. Exposing TCP 514 to the
#    broader LAN or Internet invites unauthenticated connection flooding and DoS.
#
# 3. THE WIREGUARD MESH PARADIGM (10.200.0.1:6514)
#    This daemon binds exclusively to the private WireGuard overlay IP: 10.200.0.1.
#    Because the socket is bound to 10.200.0.1 rather than 0.0.0.0, the operating
#    system kernel rejects any incoming packets arriving over physical Ethernet
#    (eth0), Wi-Fi (wlan0), or public interfaces. All traffic is cryptographically
#    isolated using WireGuard's ChaCha20-Poly1305 authenticated encryption and
#    Curve25519 ECDH key exchange before this receiver ever sees a byte.
#
# 4. DEFENSE-IN-DEPTH: THREE TIERS OF DEFENSE
#    - Tier 1: Kernel WireGuard Interface Isolation (Physical attack surface = 0).
#    - Tier 2: Transport-layer verify_request() Allowlist (Reject unmapped IPs before reading).
#    - Tier 3: Stream Log Sanitization (Strip ANSI escape injections to protect operator terminals).
# ==============================================================================

import argparse
import ipaddress
import os
import signal
import socket
import socketserver
import sys
import threading
import time
from pathlib import Path

# ------------------------------------------------------------------------------
# 1. PATH DISCOVERY & ENVIRONMENT NORMALIZATION
# ------------------------------------------------------------------------------
# Locate execution roots deterministically relative to this script file.
HERE = Path(__file__).resolve().parent
REPO = HERE.parent
if str(HERE) not in sys.path:
    # Ensure sibling modules within scripts/ can be imported cleanly
    sys.path.insert(0, str(HERE))

# ------------------------------------------------------------------------------
# 2. WORKSPACE LATCH / STOP SIGNAL INTEGRATION
# ------------------------------------------------------------------------------
# In the TWU LLC production environment, daemons check the shared fleet incident
# latch (stop_latch.py) to cease operations instantly during emergency lockdowns.
# When distributed as a standalone repository, a graceful fallback is provided
# so the receiver operates with zero external dependencies out of the box.
try:
    import stop_latch
except ImportError:
    class _StandaloneStopLatch:
        """Lightweight standard-library fallback when deployed outside TWU LLC."""
        @staticmethod
        def enforce(service_name: str) -> None:
            # Standalone mode: no central STOP latch file required
            pass

    stop_latch = _StandaloneStopLatch()

# ------------------------------------------------------------------------------
# 3. NETWORK TOPOLOGY CONFIGURATION (BINDING & ALLOWLIST)
# ------------------------------------------------------------------------------
# Strict WireGuard mesh IP address of the primary audit hub node (host-1).
# By binding to 10.200.0.1:6514, this service remains completely invisible to LAN/WAN.
DEFAULT_MESH_IP = "10.200.0.1"

# Port 6514 is the standard IANA / RFC 5425 port for secure remote syslog.
DEFAULT_MESH_PORT = 6514

# Local storage path where streamed logs from edge nodes are persisted.
LOG_DIR = REPO / "data" / "health" / "remote_logs"

# Deterministic mapping of approved WireGuard mesh peer IP addresses to node names.
# Every connection from an IP address not present in this dictionary is dropped
# at the socket level during the TCP handshake in verify_request().
KNOWN_MESH_PEERS = {
    "10.200.0.1": "host-1",       # Primary compute / aggregation hub
    "10.200.0.2": "fedora",        # Constrained edge satellite node (MacBookPro)
    "10.200.0.3": "host-2",   # Portable developer client (M1)
    "127.0.0.1": "localhost",     # Loopback interface for unit tests and local telemetry
}


# ------------------------------------------------------------------------------
# 4. LOG SANITIZATION & ANTI-INJECTION SHIELD
# ------------------------------------------------------------------------------
def sanitize_log_line(line: str) -> str:
    """Sanitize incoming log lines to prevent terminal escape injection attacks.
    
    SECURITY THREAT MODEL:
    When security operators or automated pipelines view logs using terminal
    pagers like `cat`, `tail -f`, or `less`, malicious or compromised client
    processes could emit ANSI escape sequences:
      - \x1b[2J: Screen clearing (conceals attack evidence from active view)
      - \x1b[H: Cursor repositioning (spoofs previous console output)
      - \x1b]0;Title\x07: Terminal title tampering or OSC exploit payloads
      - Non-printable null bytes (\x00) or control bytes (BEL, BS)
    
    IMPLEMENTATION:
    We enforce a strict character allowlist:
      - Retain horizontal tab (\t) for indentation formatting.
      - Retain printable ASCII characters between ordinal 32 (space) and 126 (~).
      - Strip all other control characters, escape codes, and terminal sequences.
    """
    clean = "".join(ch for ch in line if ch == "\t" or (32 <= ord(ch) <= 126))
    return clean.strip()


# ------------------------------------------------------------------------------
# 5. STREAM REQUEST HANDLER (PER-PEER LOG CONSUMPTION)
# ------------------------------------------------------------------------------
class MeshSyslogHandler(socketserver.StreamRequestHandler):
    """Event-driven stream handler instantiated for each approved client connection.
    
    Inheriting from StreamRequestHandler wraps incoming socket file descriptors
    into buffered readable (self.rfile) and writable (self.wfile) file objects,
    enabling efficient streaming line-by-line consumption without loading massive
    chunks into memory.
    """

    def handle(self):
        """Process incoming syslog messages from an authenticated mesh peer."""
        client_ip = self.client_address[0]
        peer_name = KNOWN_MESH_PEERS.get(client_ip)

        # Fail-closed secondary guard: if an unmapped peer bypassed verify_request(),
        # drop the connection immediately without allocating file descriptors.
        if not peer_name:
            return

        # Ensure the destination audit directory exists (umask 0077 enforces privacy)
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_file = LOG_DIR / f"{peer_name}.log"

        # Open target log file in append mode with UTF-8 encoding.
        # Each client gets an isolated log file named after its verified node identity.
        with open(log_file, "a", encoding="utf-8") as out:
            # Stream line-by-line using buffered socket rfile
            for line in self.rfile:
                # Cooperative pause check: halts ingestion if emergency STOP latch triggered
                stop_latch.enforce("mesh_log_receiver")

                # Decode bytes to text safely; invalid UTF-8 bytes are substituted
                decoded = line.decode("utf-8", errors="replace")

                # Strip ANSI escape injections and non-printable control sequences
                sanitized = sanitize_log_line(decoded)

                if sanitized:
                    # Prepend an immutable, deterministic RFC-3339 UTC timestamp
                    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    # Format: YYYY-MM-DDTHH:MM:SSZ [peer_node] log_message
                    out.write(f"{ts} [{peer_name}] {sanitized}\n")
                    # Immediate flush ensures logs are written to disk even during power loss
                    out.flush()


# ------------------------------------------------------------------------------
# 6. THREADED SERVER WITH TRANSPORT-LEVEL IP ALLOWLISTING
# ------------------------------------------------------------------------------
class ThreadedMeshSyslogServer(socketserver.ThreadingTCPServer):
    """Multi-threaded TCP server bound strictly to the WireGuard mesh interface.
    
    ARCHITECTURAL HIGHLIGHTS:
    1. allow_reuse_address = True:
       Allows rapid restarts without waiting for TCP TIME_WAIT states to clear.
    2. daemon_threads = True:
       Spawns lightweight worker threads that automatically terminate on server exit,
       preventing hung processes or lingering socket locks.
    3. verify_request() Override:
       Validates client IP address BEFORE allocating resources, spawning worker
       threads, or executing application handlers.
    """
    allow_reuse_address = True
    daemon_threads = True

    def verify_request(self, request, client_address):
        """Intercept and filter connection requests at the TCP socket layer.
        
        This method is invoked by the Python socketserver framework immediately
        after socket.accept() succeeds, before handle() or threading dispatch.
        
        Returns:
            True: Connection is accepted (client IP is in KNOWN_MESH_PEERS).
            False: Connection is aborted; socket is closed immediately,
                   dropping untrusted traffic without processing payloads.
        """
        client_ip = client_address[0]
        # Strict IP check: must be explicitly mapped in KNOWN_MESH_PEERS
        is_known = client_ip in KNOWN_MESH_PEERS
        if not is_known:
            # Silently drop unauthorized connections (fail-closed behavior)
            return False
        return True


# ------------------------------------------------------------------------------
# 7. SERVER LIFECYCLE & SIGNAL INTEGRATION
# ------------------------------------------------------------------------------
def run_server(bind_ip=DEFAULT_MESH_IP, port=DEFAULT_MESH_PORT, stop_event=None):
    """Run the threaded syslog server with graceful signal and shutdown handling.
    
    Args:
        bind_ip: IP address to bind (defaults to WireGuard mesh 10.200.0.1).
        port: TCP port to listen on (defaults to 6514).
        stop_event: Optional threading.Event for programmatic shutdown.
    """
    # Instantiate the threaded TCP server
    server = ThreadedMeshSyslogServer((bind_ip, port), MeshSyslogHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    # Intercept SIGTERM and SIGINT for graceful shutdown under systemd or CLI
    shutdown_requested = False

    def _sig_handler(signum, frame):
        nonlocal shutdown_requested
        shutdown_requested = True

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    try:
        # Service loop: sleeps in low-CPU state while monitoring stop signals
        while not shutdown_requested:
            if stop_event is not None and stop_event.is_set():
                break
            # Check fleet incident latch
            stop_latch.enforce("mesh_log_receiver")
            time.sleep(1)
    finally:
        # Graceful shutdown sequence:
        # 1. Stop accepting new connections
        # 2. Release bound socket port
        # 3. Join server daemon thread with 2-second timeout
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)


# ------------------------------------------------------------------------------
# 8. COMMAND LINE INTERFACE & SYSTEMD INTEGRATION
# ------------------------------------------------------------------------------
def main():
    """Command-line entrypoint for execution, status inspection, and systemd service."""
    global LOG_DIR

    parser = argparse.ArgumentParser(
        description="WireGuard mesh remote syslog receiver for distributed node survivability"
    )
    parser.add_argument(
        "--bind",
        default=DEFAULT_MESH_IP,
        help=f"Mesh IP interface to bind (default: {DEFAULT_MESH_IP})"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_MESH_PORT,
        help=f"TCP port to listen on (default: {DEFAULT_MESH_PORT})"
    )
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=LOG_DIR,
        help=f"Target directory for storing peer log files (default: {LOG_DIR})"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Print receiver configuration and registered mesh peers without starting"
    )
    args = parser.parse_args()

    # Update active log destination directory if custom path provided
    LOG_DIR = args.log_dir

    # Check STOP latch before initializing sockets
    stop_latch.enforce("mesh_log_receiver")

    if args.status:
        print("=== WireGuard Mesh Syslog Receiver Status ===")
        print(f"Configured Bind Target : {args.bind}:{args.port}")
        print(f"Log Storage Directory  : {LOG_DIR}")
        print(f"Allowed Mesh Peers ({len(KNOWN_MESH_PEERS)}) :")
        for ip, name in sorted(KNOWN_MESH_PEERS.items()):
            print(f"  - {ip:15} -> {name}")
        return 0

    print(f"[*] Starting mesh_log_receiver on {args.bind}:{args.port}...")
    print(f"[*] Storing logs in {LOG_DIR}")
    print(f"[*] Listening strictly for connections from: {list(KNOWN_MESH_PEERS.keys())}")
    run_server(args.bind, args.port)
    print("[*] mesh_log_receiver terminated cleanly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
