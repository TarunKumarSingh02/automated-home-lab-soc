
import unittest
import tempfile
from pathlib import Path

from integrations.ssh_detector import detect_ssh_attacks


class TestSSHDetector(unittest.TestCase):

    def run_detector(self, events):
        with tempfile.TemporaryDirectory() as directory:
            log_file = Path(directory) / "test.log"
            log_file.write_text("\n".join(events), encoding="utf-8")
            return detect_ssh_attacks(log_file)

    def test_repeated_failed_logins(self):
        events = [
            f"2026-11-09T10:0{i}:00Z Failed password "
            f"for invalid user admin from 192.0.2.10 "
            f"port 5010{i} ssh2"
            for i in range(3)
        ]
        self.assertEqual(len(self.run_detector(events)), 1)

    def test_successful_login(self):
        events = [
            "2026-11-09T10:00:00Z Accepted password "
            "for vboxuser from 192.168.56.1 port 5000 ssh2"
        ]
        self.assertEqual(len(self.run_detector(events)), 0)

    def test_failures_outside_window(self):
        events = [
            f"2026-11-09T10:{i:02d}:00Z Failed password "
            f"for admin from 192.0.2.10 port 5000 ssh2"
            for i in (0, 6, 12)
        ]
        self.assertEqual(len(self.run_detector(events)), 0)


if __name__ == "__main__":
    unittest.main()
