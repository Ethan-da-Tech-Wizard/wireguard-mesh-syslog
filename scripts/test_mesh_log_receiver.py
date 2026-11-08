#!/usr/bin/env python3
# ==============================================================================
# Unit Tests for WireGuard Mesh Remote Syslog Receiver
# ==============================================================================
# File: scripts/test_mesh_log_receiver.py
# Architecture: Zero-dependency, test-driven validation for mesh logging subsystem
# Scope: Test socket peer filtering, log sanitization, RFC 5424/3164 parsing,
#        octet counting framing vs non-transparent framing, CIDR subnet matching,
#        and live TCP loopback ingest
# Author: Tech Wizard <author@users.noreply.invalid>
# Organization: TWU LLC
# License: MIT License (c) 2026 Tech Wizard, TWU LLC
# ==============================================================================
#
# EDUCATIONAL WALKTHROUGH & TEST DESIGN:
#
# 1. TEST ISOLATION & DETERMINISM:
#    To ensure zero interference with production log repositories or other system
#    processes, tests run on ephemeral TCP ports (port 0 assigned by the operating
#    system kernel) and write exclusively to disposable temporary directories
#    managed by tempfile.TemporaryDirectory().
#
# 2. VALIDATION COVERAGE:
#    - Security Sanitization: Stripping ANSI terminal injections (escape codes,
#      screen clears, cursor jumps, null bytes) to protect administrative terminals.
#      See Lynis LOGG-2154 defense-in-depth principles.
#    - Socket Layer Verification: Enforcing transport-level peer allowlists in
#      verify_request() before worker threads or read buffers are allocated.
#    - CIDR Subnet Math: Testing boundary conditions of 10.200.0.0/24.
#    - Protocol Parsing: Bitwise PRI verification (`Facility * 8 + Severity`),
#      RFC 5424 structured data extraction, and RFC 3164 BSD legacy format parsing.
#    - Framing Ingestion: Validating both traditional non-transparent newline framing
#      and RFC 6587 Section 3.4.1 octet counting framing.
# ==============================================================================

import os
import signal
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

# Path configuration for standalone execution
HERE = Path(__file__).resolve().parent
REPO = HERE.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import mesh_log_receiver


class TestMeshLogReceiver(unittest.TestCase):
    """Test suite for mesh_log_receiver security, filtering, and ingestion logic."""

    def test_sanitize_log_line(self):
        """Verify that ANSI escape sequences and non-printable control characters are stripped.
        
        THREAT MODEL TEST:
        An attacker or compromised process emits ANSI terminal escape sequences:
          `\x1b[31m`: ANSI Red Foreground
          `\x1b[0m` : ANSI Reset
          `\x00`    : Null byte (can truncate C-string log parsers)
          `\x07`    : Bell control character
        All must be stripped cleanly while preserving authentic ASCII message text.
        """
        dirty = "\x1b[31mCRITICAL\x1b[0m auth failure\x00\x07"
        cleaned = mesh_log_receiver.sanitize_log_line(dirty)
        self.assertNotIn("\x1b", cleaned, "ANSI escape characters must be stripped")
        self.assertNotIn("\x00", cleaned, "Null bytes must be stripped")
        self.assertNotIn("\x07", cleaned, "Bell control characters must be stripped")
        self.assertIn("CRITICAL", cleaned, "Legitimate log content must be preserved")
        self.assertIn("auth failure", cleaned, "Legitimate log content must be preserved")

    def test_verify_request_allowed_and_rejected(self):
        """Verify that verify_request() strictly enforces the KNOWN_MESH_PEERS allowlist.
        
        SECURITY VALIDATION:
        The server overrides socketserver.ThreadingTCPServer.verify_request().
        Connections from mapped IPs must return True; unmapped external IPs must
        return False, causing the server to abort the socket handshake immediately.
        """
        server = mesh_log_receiver.ThreadedMeshSyslogServer(
            ("127.0.0.1", 0), mesh_log_receiver.MeshSyslogHandler
        )
        try:
            # 127.0.0.1 and 10.200.0.3 are registered mesh peers -> must be accepted
            self.assertTrue(server.verify_request(None, ("127.0.0.1", 12345)))
            self.assertTrue(server.verify_request(None, ("10.200.0.3", 54321)))
            self.assertTrue(server.verify_request(None, ("10.200.0.2", 44321)))

            # Arbitrary external / unauthenticated IP addresses -> must be rejected
            self.assertFalse(server.verify_request(None, ("192.168.1.100", 12345)))
            self.assertFalse(server.verify_request(None, ("8.8.8.8", 12345)))
            self.assertFalse(server.verify_request(None, ("10.200.0.99", 12345)))
        finally:
            server.server_close()

    def test_cidr_mesh_subnet_validation(self):
        """Verify CIDR IP containment logic for 10.200.0.0/24 and loopback addresses.
        
        Tests network boundaries of the WireGuard point-to-point mesh overlay.
        """
        # Approved mesh range (10.200.0.1 - 10.200.0.254) and loopback
        self.assertTrue(mesh_log_receiver.is_ip_in_mesh_subnet("10.200.0.1"))
        self.assertTrue(mesh_log_receiver.is_ip_in_mesh_subnet("10.200.0.2"))
        self.assertTrue(mesh_log_receiver.is_ip_in_mesh_subnet("10.200.0.254"))
        self.assertTrue(mesh_log_receiver.is_ip_in_mesh_subnet("127.0.0.1"))

        # Outside the /24 subnet boundary -> False
        self.assertFalse(mesh_log_receiver.is_ip_in_mesh_subnet("10.77.1.1"))
        self.assertFalse(mesh_log_receiver.is_ip_in_mesh_subnet("192.168.1.1"))
        self.assertFalse(mesh_log_receiver.is_ip_in_mesh_subnet("172.16.0.1"))
        self.assertFalse(mesh_log_receiver.is_ip_in_mesh_subnet("8.8.8.8"))

        # Malformed IP strings must fail closed -> False
        self.assertFalse(mesh_log_receiver.is_ip_in_mesh_subnet("not-an-ip"))
        self.assertFalse(mesh_log_receiver.is_ip_in_mesh_subnet(""))

    def test_parse_syslog_rfc5424(self):
        """Verify parsing of modern RFC 5424 structured syslog messages.
        
        RFC 5424 format:
        <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
        
        PRI <34>:
          PRI = (Facility * 8) + Severity
          Facility = 34 // 8 = 4 ("auth")
          Severity = 34 % 8  = 2 ("crit")
        """
        raw = '<34>1 2026-11-08T07:22:45.123456Z fedora sshd 1234 ID47 [meta ip="10.200.0.2"] Key auth failed'
        parsed = mesh_log_receiver.parse_syslog_message(raw)

        self.assertEqual(parsed["format"], "RFC5424")
        self.assertEqual(parsed["pri"], 34)
        self.assertEqual(parsed["facility"], 4)
        self.assertEqual(parsed["facility_name"], "auth")
        self.assertEqual(parsed["severity"], 2)
        self.assertEqual(parsed["severity_name"], "crit")
        self.assertEqual(parsed["timestamp"], "2026-11-08T07:22:45.123456Z")
        self.assertEqual(parsed["hostname"], "fedora")
        self.assertEqual(parsed["app_name"], "sshd")
        self.assertEqual(parsed["proc_id"], "1234")
        self.assertEqual(parsed["msg_id"], "ID47")
        self.assertEqual(parsed["structured_data"], '[meta ip="10.200.0.2"]')
        self.assertEqual(parsed["message"], "Key auth failed")

    def test_parse_syslog_rfc3164(self):
        """Verify parsing of legacy BSD RFC 3164 syslog messages.
        
        RFC 3164 format:
        <PRI>TIMESTAMP HOSTNAME TAG: MSG
        
        PRI <13>:
          Facility = 13 // 8 = 1 ("user")
          Severity = 13 % 8  = 5 ("notice")
        """
        raw = "<13>Nov  8 07:22:45 fedora audit[4321]: System call executed"
        parsed = mesh_log_receiver.parse_syslog_message(raw)

        self.assertEqual(parsed["format"], "RFC3164")
        self.assertEqual(parsed["pri"], 13)
        self.assertEqual(parsed["facility"], 1)
        self.assertEqual(parsed["facility_name"], "user")
        self.assertEqual(parsed["severity"], 5)
        self.assertEqual(parsed["severity_name"], "notice")
        self.assertEqual(parsed["timestamp"], "Nov  8 07:22:45")
        self.assertEqual(parsed["hostname"], "fedora")
        self.assertEqual(parsed["app_name"], "audit[4321]")
        self.assertEqual(parsed["message"], "System call executed")

    def test_live_loopback_log_ingest(self):
        """Test end-to-end TCP connection, message transmission, and atomic file write."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            temp_log_dir = Path(tmp_dir)
            orig_log_dir = mesh_log_receiver.LOG_DIR
            mesh_log_receiver.LOG_DIR = temp_log_dir

            server = mesh_log_receiver.ThreadedMeshSyslogServer(
                ("127.0.0.1", 0), mesh_log_receiver.MeshSyslogHandler
            )
            port = server.server_address[1]
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()

            log_path = temp_log_dir / "localhost.log"
            test_msg = f"TEST_AUDIT_LOG_ENTRY_{int(time.time())}\n"

            try:
                # Open TCP connection simulating a mesh client
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(("127.0.0.1", port))
                s.sendall(test_msg.encode("utf-8"))
                s.close()

                # Allow brief window for disk write
                time.sleep(0.2)
                self.assertTrue(log_path.exists(), "Log file for peer must be created")
                content = log_path.read_text(encoding="utf-8")
                self.assertIn("[localhost]", content, "Log entry must include peer identifier")
                self.assertIn(test_msg.strip(), content, "Log entry must contain payload text")
            finally:
                server.shutdown()
                server.server_close()
                server_thread.join(timeout=2)
                mesh_log_receiver.LOG_DIR = orig_log_dir

    def test_live_octet_counting_framing_ingest(self):
        """Test end-to-end ingestion using RFC 6587 Section 3.4.1 Octet Counting Framing.
        
        Verifies that length-prefixed framing `<MSGLEN> <MSG>` is received,
        stripped of its framing header, and logged accurately.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            temp_log_dir = Path(tmp_dir)
            orig_log_dir = mesh_log_receiver.LOG_DIR
            mesh_log_receiver.LOG_DIR = temp_log_dir

            server = mesh_log_receiver.ThreadedMeshSyslogServer(
                ("127.0.0.1", 0), mesh_log_receiver.MeshSyslogHandler
            )
            port = server.server_address[1]
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()

            log_path = temp_log_dir / "localhost.log"
            raw_payload = "OCTET_COUNTED_AUDIT_EVENT_PAYLOAD"
            # Octet counting frame: "<MSGLEN> <PAYLOAD>\n"
            frame = f"{len(raw_payload)} {raw_payload}\n"

            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(("127.0.0.1", port))
                s.sendall(frame.encode("utf-8"))
                s.close()

                time.sleep(0.2)
                self.assertTrue(log_path.exists(), "Log file for peer must be created")
                content = log_path.read_text(encoding="utf-8")
                self.assertIn("[localhost]", content)
                self.assertIn(raw_payload, content)
            finally:
                server.shutdown()
                server.server_close()
                server_thread.join(timeout=2)
                mesh_log_receiver.LOG_DIR = orig_log_dir


if __name__ == "__main__":
    unittest.main()
