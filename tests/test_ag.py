import contextlib
import io
import pathlib
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
        self.assertEqual(message, "Connected")
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
        self.assertIn("not available yet", message)

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
        self.assertIn("API communication errors", rendered)
        self.assertIn("result delivery failures", rendered)
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


if __name__ == "__main__":
    unittest.main()
