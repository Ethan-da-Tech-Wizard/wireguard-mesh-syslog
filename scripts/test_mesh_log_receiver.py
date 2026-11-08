#!/usr/bin/env python3
# ==============================================================================
# Unit Tests for WireGuard Mesh Remote Syslog Receiver
# ==============================================================================
# File: scripts/test_mesh_log_receiver.py
# Scope: Test socket peer filtering, log sanitization, live TCP loopback ingest
# ==============================================================================

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
        """Verify that ANSI escape sequences and non-printable control characters are stripped."""
        # Contains red color code, reset code, null byte, bell character
        dirty = "\x1b[31mCRITICAL\x1b[0m auth failure\x00\x07"
        cleaned = mesh_log_receiver.sanitize_log_line(dirty)
        self.assertNotIn("\x1b", cleaned, "ANSI escape characters must be stripped")
        self.assertNotIn("\x00", cleaned, "Null bytes must be stripped")
        self.assertNotIn("\x07", cleaned, "Bell control characters must be stripped")
        self.assertIn("CRITICAL", cleaned, "Legitimate log content must be preserved")
        self.assertIn("auth failure", cleaned, "Legitimate log content must be preserved")

    def test_verify_request_allowed_and_rejected(self):
        """Verify that verify_request() strictly enforces the KNOWN_MESH_PEERS allowlist."""
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


if __name__ == "__main__":
    unittest.main()
