import contextlib
import io
import os
import pathlib
import subprocess
import sys
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import ag  # noqa: E402


class ControlConsoleTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "api_base_url": "https://www.ppflight.com/api/looking-glass/v1",
            "request_timeout_seconds": 10,
            "state_path": "/state.json",
        }

    @mock.patch.object(ag.agent, "load_json_file")
    @mock.patch.object(ag.agent, "ApiClient")
    def test_summary_only_returns_whitelisted_anonymous_fields(self, client_class, load_state):
        load_state.return_value = {"agent_token": "x" * 64, "agent_uuid": "node-safe"}
        client_class.return_value.post.return_value = {
            "data": {
                "node": {
                    "id": "node-safe",
                    "code": "test",
                    "name": "Test Node",
                    "target": "must-not-display.example",
                    "token": "must-not-display-token",
                },
                "stats": {
                    "total_24h": 7,
                    "anonymous_visitor_fingerprint_count": 3,
                    "security_rejections_24h": 2,
                    "active_ip_block_count": 4,
                    "status_counts": {"completed": 5, "failed": 2, "secret_status": 99},
                    "visitor_ip": "203.0.113.8",
                    "result": "must not display",
                },
            }
        }
        message, summary = ag.fetch_summary(self.config)
        self.assertEqual(message, "已连接")
        self.assertEqual(summary["node"], {"id": "node-safe", "code": "test", "name": "Test Node"})
        self.assertEqual(summary["stats"], {
            "total_24h": 7,
            "anonymous_visitor_fingerprint_count": 3,
            "security_rejections_24h": 2,
            "active_ip_block_count": 4,
            "status_counts": {"completed": 5, "failed": 2},
        })
        client_class.return_value.post.assert_called_once_with("agent/control/summary", {})

    @mock.patch.object(ag.agent, "load_json_file", return_value={"agent_token": "x" * 64})
    @mock.patch.object(ag.agent, "ApiClient")
    def test_missing_summary_endpoint_degrades_without_response_body(self, client_class, _state):
        client_class.return_value.post.side_effect = ag.agent.ApiHttpError(
            "agent/control/summary", 404
        )
        message, summary = ag.fetch_summary(self.config)
        self.assertIsNone(summary)
        self.assertIn("尚未提供", message)

    @mock.patch.object(ag, "fixed_command")
    @mock.patch.object(ag.shutil, "which", return_value="/usr/bin/journalctl")
    def test_log_diagnostics_never_echo_raw_messages(self, _which, command):
        command.return_value = (0, "\n".join([
            '{"MESSAGE":"agent API error for victim.example target 8.8.8.8",'
            '"PRIORITY":"3","__REALTIME_TIMESTAMP":"1720000000000000"}',
            '{"MESSAGE":"completion delivery failed for job secret-job-id",'
            '"PRIORITY":"4","__REALTIME_TIMESTAMP":"1720000001000000"}',
        ]))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            ag.print_log_diagnostics()
        rendered = output.getvalue()
        self.assertIn("API 通信错误", rendered)
        self.assertIn("结果提交失败", rendered)
        self.assertNotIn("victim.example", rendered)
        self.assertNotIn("8.8.8.8", rendered)
        self.assertNotIn("secret-job-id", rendered)

    @mock.patch.object(ag.agent, "load_json_file")
    def test_bound_identity_never_returns_token(self, load_state):
        load_state.return_value = {"agent_token": "secret-token-value" * 3, "agent_uuid": "node-id"}
        self.assertEqual(ag.bound_identity(self.config), (True, "node-id"))

    def test_noninteractive_commands_are_fixed(self):
        for command in ("status", "summary", "check", "logs", "bind", "version"):
            with self.subTest(command=command):
                self.assertEqual(ag.parse_arguments([command]).command, command)

    def test_console_forces_utf8_when_parent_requests_latin_1(self):
        environment = os.environ.copy()
        environment["PYTHONIOENCODING"] = "latin-1"
        completed = subprocess.run(
            [sys.executable, str(ROOT / "ag.py"), "--help"],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )

        self.assertEqual(
            completed.returncode,
            0,
            completed.stderr.decode("utf-8", errors="replace"),
        )
        self.assertIn("控制台", completed.stdout.decode("utf-8"))

    def test_distribution_uses_ag_lg_command_and_chinese_menu(self):
        wrapper = ROOT / "ag-lg"
        self.assertTrue(wrapper.is_file())
        self.assertTrue(os.access(wrapper, os.X_OK))
        self.assertFalse((ROOT / "ag").exists())
        self.assertIn("PPFLIGHT_LOOKING_GLASS_AG_WRAPPER=1", wrapper.read_text())

        installer = (ROOT / "install.sh").read_text()
        uninstaller = (ROOT / "uninstall.sh").read_text()
        console = (ROOT / "ag.py").read_text()
        self.assertIn('"${SOURCE_DIR}/ag-lg" "/usr/local/bin/ag-lg"', installer)
        self.assertIn('remove_owned_console_wrapper "/usr/local/bin/ag-lg"', uninstaller)
        self.assertIn('remove_owned_console_wrapper "/usr/local/bin/ag"', uninstaller)
        self.assertIn("[1] 刷新", console)
        self.assertIn("ag-lg status|summary|check|logs|bind|version", console)
        self.assertNotIn("[1] Refresh", console)


if __name__ == "__main__":
    unittest.main()
