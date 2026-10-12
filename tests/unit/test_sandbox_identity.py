import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentporter.sandbox.bubblewrap import BubblewrapSandbox


class IdentityTests(unittest.TestCase):
    def test_stale_records_replaced_on_init_and_every_launch(self):
        with tempfile.TemporaryDirectory() as root:
            state = Path(root)
            (state / "etc").mkdir()
            for name in ("passwd", "group"):
                (state / "etc" / name).write_text("sandbox:x:1000:1000:stale\n")
            with patch("os.getuid", return_value=2056259175), patch("os.getgid", return_value=12345):
                sandbox = BubblewrapSandbox(state)
                self.assertIn("sandbox:x:2056259175:12345:", sandbox.passwd_file.read_text())
                self.assertIn("sandbox:x:12345:", sandbox.group_file.read_text())
                sandbox.passwd_file.write_text("stale\n")
                sandbox.build_bwrap_args(root)
                self.assertIn("sandbox:x:2056259175:12345:", sandbox.passwd_file.read_text())
                self.assertEqual(sandbox.passwd_file.stat().st_mode & 0o777, 0o600)
                self.assertEqual(list(sandbox.etc_dir.glob(".identity-*")), [])

    def test_identity_symlink_replaced_without_modifying_target(self):
        with tempfile.TemporaryDirectory() as root:
            state = Path(root)
            (state / "etc").mkdir()
            target = state / "synthetic-target"
            target.write_text("unchanged")
            (state / "etc" / "passwd").symlink_to(target)
            sandbox = BubblewrapSandbox(state)
            self.assertFalse(sandbox.passwd_file.is_symlink())
            self.assertEqual(target.read_text(), "unchanged")
