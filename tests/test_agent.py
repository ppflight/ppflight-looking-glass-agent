import contextlib
import importlib.util
import io
import pathlib
import sys
import time
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "agent.py"
SPEC = importlib.util.spec_from_file_location("ppflight_agent", MODULE_PATH)
agent = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = agent
SPEC.loader.exec_module(agent)


def claimed_job(**overrides):
    value = {
        "id": "12345678-abcd",
        "method": "ping",
        "target": "example.com",
        "resolved_addresses": ["1.1.1.1"],
        "resolution_fingerprint": agent.hashlib.sha256(b"1.1.1.1").hexdigest(),
        "execution_contract": {"version": 1, "timeout_seconds": 15},
        "deadline_at": "2026-08-23T18:00:15+00:00",
    }
    value.update(overrides)
    return {"data": {"job": value}}


class TargetValidationTests(unittest.TestCase):
    def test_normalizes_domain_and_public_ip(self):
        self.assertEqual(agent.normalize_target(" Example.COM. "), "example.com")
        self.assertEqual(agent.normalize_target("1.1.1.1"), "1.1.1.1")
        self.assertEqual(agent.normalize_target("2606:4700:4700::1111"), "2606:4700:4700::1111")

    def test_rejects_urls_ports_and_parameters(self):
        invalid = [
            "https://example.com",
            "example.com:443",
            "1.1.1.1:53",
            "example.com/path",
            "example.com -c 100",
            "example.com;id",
            "[2606:4700:4700::1111]",
            "fe80::1%eth0",
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(agent.TargetRejected):
                agent.normalize_target(value)

    def test_rejects_non_public_literals_and_metadata(self):
        invalid = [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "100.100.100.200",
            "100.64.0.1",
            "224.0.0.1",
            "192.0.2.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "64:ff9b:1::1",
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(agent.TargetRejected):
                agent.resolve_public_target(value)

    @mock.patch.object(agent, "_resolve_hostname_with_deadline")
    def test_rejects_domain_if_any_answer_is_private(self, resolve):
        resolve.return_value = ("1.1.1.1", "10.0.0.8")
        with self.assertRaises(agent.TargetRejected):
            agent.resolve_public_target("example.com")

    @mock.patch.object(agent.multiprocessing, "get_context")
    def test_stuck_dns_process_is_terminated_at_deadline(self, get_context):
        context = get_context.return_value
        receiver = mock.Mock()
        sender = mock.Mock()
        context.Pipe.return_value = (receiver, sender)
        process = context.Process.return_value
        process.pid = 321
        process.is_alive.side_effect = [True, False]
        receiver.poll.return_value = False

        with self.assertRaises(agent.TaskDeadlineExceeded):
            agent._resolve_hostname_with_deadline(
                "example.com", time.monotonic() + 0.01
            )

        get_context.assert_called_once_with("spawn")
        process.start.assert_called_once_with()
        process.terminate.assert_called_once_with()
        process.join.assert_called_once_with(timeout=0.25)

    @mock.patch.object(agent, "resolve_public_target")
    def test_rejects_dns_change_between_validation_and_execution(self, resolve):
        resolve.side_effect = [
            agent.ResolvedTarget("example.com", ("1.1.1.1",)),
            agent.ResolvedTarget("example.com", ("8.8.8.8",)),
        ]
        with self.assertRaises(agent.TargetRejected):
            agent.resolve_and_pin("example.com")

    @mock.patch.object(agent, "resolve_public_target")
    def test_pins_literal_after_two_identical_resolutions(self, resolve):
        resolved = agent.ResolvedTarget("example.com", ("2606:4700:4700::1111", "1.1.1.1"))
        resolve.side_effect = [resolved, resolved]
        result = agent.resolve_and_pin("example.com")
        self.assertEqual(result.pinned_ip, "1.1.1.1")
        self.assertEqual(resolve.call_count, 2)


class FixedCommandTests(unittest.TestCase):
    @mock.patch.object(agent, "find_binary", side_effect=lambda name: "/usr/bin/" + name)
    def test_ping_arguments_are_fixed(self, _find):
        command = agent.build_command("ping", "1.1.1.1")
        self.assertEqual(
            command,
            ["/usr/bin/ping", "-4", "-n", "-c", "5", "-W", "2", "1.1.1.1"],
        )

    @mock.patch.object(agent, "find_binary", side_effect=lambda name: "/usr/bin/" + name)
    def test_trace_and_mtr_limits_are_fixed(self, _find):
        trace = agent.build_command("trace", "1.1.1.1")
        mtr = agent.build_command("mtr", "2606:4700:4700::1111")
        self.assertEqual(trace[trace.index("-m") + 1], "20")
        self.assertEqual(mtr[mtr.index("--report-cycles") + 1], "5")
        self.assertEqual(mtr[mtr.index("--interval") + 1], "1.0")
        self.assertEqual(mtr[mtr.index("--max-ttl") + 1], "20")
        self.assertEqual(mtr[1], "-6")

    def test_unknown_tool_is_rejected(self):
        with self.assertRaises(agent.AgentError):
            agent.build_command("curl", "1.1.1.1")

    def test_output_is_limited_to_64_kib(self):
        output, truncated = agent.truncate_utf8(b"x" * (agent.MAX_OUTPUT_BYTES + 100))
        self.assertTrue(truncated)
        self.assertLessEqual(len(output.encode("utf-8")), agent.MAX_OUTPUT_BYTES)
        self.assertIn("output truncated", output)

    def test_subprocess_capture_is_bounded_while_reading(self):
        command = [
            sys.executable,
            "-c",
            "import os,time; os.write(1, b'x' * (1024 * 1024)); time.sleep(5)",
        ]
        started = time.monotonic()
        result = agent.run_fixed_command(command, timeout=3)

        self.assertTrue(result["truncated"])
        self.assertFalse(result["timed_out"])
        self.assertLess(time.monotonic() - started, 2)
        self.assertLessEqual(
            len(result["output"].encode("utf-8")), agent.MAX_OUTPUT_BYTES
        )
        self.assertIn("output truncated", result["output"])
        self.assertLess(result["exit_code"], 0)

    def test_silent_subprocess_is_killed_at_timeout(self):
        result = agent.run_fixed_command(
            [sys.executable, "-c", "import time; time.sleep(2)"], timeout=0.05
        )
        self.assertTrue(result["timed_out"])
        self.assertLess(result["duration_ms"], 1000)

    def test_output_lines_match_laravel_bounds(self):
        lines = agent.output_lines(("é" * 700 + "\n") * 300)
        self.assertLessEqual(len(lines), 256)
        self.assertTrue(all(len(line.encode("utf-8")) <= 1024 for line in lines))
        encoded = agent.json.dumps({"output": lines}, ensure_ascii=False).encode("utf-8")
        self.assertLessEqual(len(encoded), agent.MAX_OUTPUT_BYTES - 1024)

    def test_private_hops_are_redacted(self):
        raw = "1 10.0.0.1 1 ms\n2 192.168.1.1 2 ms\n3 1.1.1.1 3 ms\n4 fd00::1 4 ms"
        redacted = agent.redact_non_public_hops(raw)
        self.assertNotIn("10.0.0.1", redacted)
        self.assertNotIn("192.168.1.1", redacted)
        self.assertNotIn("fd00::1", redacted)
        self.assertEqual(redacted.count("private hop"), 3)
        self.assertIn("1.1.1.1", redacted)


class ProtocolTests(unittest.TestCase):
    def test_api_redirects_are_never_followed(self):
        handler = agent._NoRedirectHandler()
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "http://evil.test"))

    def test_claim_only_accepts_known_tool_and_safe_uuid(self):
        fingerprint = agent.hashlib.sha256(b"1.1.1.1").hexdigest()
        job = agent.normalize_job(claimed_job(method="trace"))
        self.assertEqual(job["method"], "trace")
        with self.assertRaises(agent.AgentError):
            agent.normalize_job(
                {"data": {"job": {
                    "id": "12345678-abcd",
                    "method": "curl",
                    "target": "x",
                    "resolved_addresses": ["1.1.1.1"],
                    "resolution_fingerprint": fingerprint,
                }}}
            )

    def test_claim_preserves_server_ipv6_spelling_for_resolution_proof(self):
        expanded = "2606:4700:4700:0000:0000:0000:0000:1111"
        fingerprint = agent.hashlib.sha256(expanded.encode("utf-8")).hexdigest()
        job = agent.normalize_job({"data": {"job": {
            "id": "12345678-abcd",
            "method": "ping",
            "target": expanded,
            "resolved_addresses": [expanded],
            "resolution_fingerprint": fingerprint,
            "execution_contract": {"version": 1, "timeout_seconds": 15},
            "deadline_at": "2026-08-23T18:00:15Z",
        }}})
        self.assertEqual(job["resolved_addresses"], [expanded])
        self.assertEqual(job["canonical_addresses"], ["2606:4700:4700::1111"])

    def test_empty_claim_is_not_a_job(self):
        self.assertIsNone(agent.normalize_job({"data": None}))
        self.assertIsNone(agent.normalize_job({"data": {}}))

    def test_config_requires_https(self):
        with self.assertRaises(agent.AgentError):
            agent.validate_config({"api_base_url": "http://www.ppflight.com/api"})
        config = agent.validate_config(
            {"api_base_url": "https://www.ppflight.com/api/looking-glass/v1"}
        )
        self.assertEqual(config["request_timeout_seconds"], 10)

    def test_capabilities_match_hard_limits(self):
        self.assertEqual(agent.capabilities(), {"methods": ["mtr", "ping", "trace"]})
        self.assertEqual(agent.MAX_TASK_SECONDS, 15)
        self.assertEqual(agent.MAX_OUTPUT_BYTES, 65536)
        self.assertEqual(agent.MAX_CONCURRENCY, 4)
        self.assertEqual(agent.COMPLETION_TRANSPORT_RESERVE_SECONDS, 1.0)

    def test_claim_requires_timezone_deadline_and_bounded_timeout_contract(self):
        for response in (
            claimed_job(deadline_at="2026-08-23T18:00:15"),
            claimed_job(deadline_at="not-a-date"),
            claimed_job(execution_contract={"version": 1, "timeout_seconds": 16}),
            claimed_job(execution_contract={"version": 1, "timeout_seconds": True}),
            claimed_job(execution_contract={"version": 2, "timeout_seconds": 15}),
        ):
            with self.subTest(response=response), self.assertRaises(agent.AgentError):
                agent.normalize_job(response)

    def test_claim_budget_starts_before_http_and_reserves_completion_second(self):
        runner = object.__new__(agent.AgentRunner)
        runner.client = mock.Mock()
        runner.client.post.return_value = claimed_job()
        runner.executor = mock.Mock()
        future = runner.executor.submit.return_value
        runner.futures = {}
        runner.completion_deadlines = {}
        runner.work_event = agent.threading.Event()

        with mock.patch.object(agent.time, "monotonic", return_value=100.0):
            self.assertTrue(runner.claim())

        submitted_job = runner.executor.submit.call_args.args[1]
        self.assertEqual(submitted_job["completion_deadline_monotonic"], 115.0)
        self.assertEqual(submitted_job["execution_deadline_monotonic"], 114.0)
        self.assertEqual(submitted_job["server_deadline_at"], "2026-08-23T18:00:15Z")
        future.add_done_callback.assert_called_once()

    def test_server_wall_clock_skew_does_not_shorten_monotonic_budget(self):
        job = agent.normalize_job(
            claimed_job(deadline_at="2000-01-01T00:00:15Z"),
            claim_started_monotonic=50.0,
        )
        self.assertEqual(job["completion_deadline_monotonic"], 65.0)
        self.assertEqual(job["execution_deadline_monotonic"], 64.0)

    def test_bind_response_extracts_real_node_shape(self):
        token = "pflg_agent_" + "x" * 64
        extracted, node_id = agent.extract_token(
            {"data": {"node": {"id": "node-uuid", "code": "LAX"}, "agent_token": token}}
        )
        self.assertEqual(extracted, token)
        self.assertEqual(node_id, "node-uuid")

    @mock.patch.object(agent, "api_architecture", return_value="x86_64")
    @mock.patch.object(agent, "api_platform", return_value="debian")
    @mock.patch.object(agent, "api_hostname", return_value="lg-test")
    def test_bind_and_heartbeat_identity_matches_api(self, _hostname, _platform, _architecture):
        self.assertEqual(agent.identity_payload({}), {
            "hostname": "lg-test",
            "agent_version": agent.VERSION,
            "platform": "debian",
            "architecture": "x86_64",
            "capabilities": {"methods": ["mtr", "ping", "trace"]},
        })

    @mock.patch.object(agent, "run_fixed_command")
    @mock.patch.object(agent, "build_command", return_value=["/usr/bin/ping"])
    @mock.patch.object(agent, "resolve_and_pin")
    def test_complete_payload_matches_laravel_contract(self, resolve, _build, run):
        resolve.return_value = agent.ResolvedTarget("example.com", ("1.1.1.1",))
        run.return_value = {
            "exit_code": 0,
            "timed_out": False,
            "truncated": False,
            "duration_ms": 12,
            "output": "1.1.1.1 ok",
        }
        fingerprint = agent.hashlib.sha256(b"1.1.1.1").hexdigest()
        payload = agent.execute_job({
            "uuid": "12345678-abcd",
            "method": "ping",
            "target": "example.com",
            "resolved_addresses": ["1.1.1.1"],
            "canonical_addresses": ["1.1.1.1"],
            "resolution_fingerprint": fingerprint,
            "execution_deadline_monotonic": time.monotonic() + 14,
        })
        self.assertEqual(payload["status"], "completed")
        self.assertEqual(payload["resolved_addresses"], ["1.1.1.1"])
        self.assertEqual(payload["resolution_fingerprint"], fingerprint)
        self.assertEqual(payload["result"]["output"], ["1.1.1.1 ok"])
        self.assertNotIn("target", payload)
        deadline = resolve.call_args.kwargs["deadline"]
        self.assertGreater(deadline, time.monotonic())
        self.assertLessEqual(run.call_args.kwargs["timeout"], agent.MAX_TASK_SECONDS)

    @mock.patch.object(
        agent,
        "resolve_and_pin",
        side_effect=agent.TaskDeadlineExceeded("Task deadline expired during DNS resolution"),
    )
    def test_dns_deadline_uses_timeout_error_shape(self, _resolve):
        payload = agent.execute_job({
            "method": "ping",
            "target": "example.com",
            "execution_deadline_monotonic": time.monotonic() + 14,
        })

    def test_queued_worker_never_restarts_expired_claim_budget(self):
        payload = agent.execute_job({
            "method": "ping",
            "target": "example.com",
            "execution_deadline_monotonic": time.monotonic() - 1,
        })
        self.assertEqual(payload["error"]["code"], "execution_timeout")
        self.assertEqual(payload, {
            "status": "failed",
            "error": {
                "code": "execution_timeout",
                "message": "Task deadline expired during DNS resolution",
            },
        })

    @mock.patch.object(agent, "resolve_and_pin", side_effect=agent.ResolutionChanged("changed"))
    def test_resolution_change_uses_api_error_shape(self, _resolve):
        payload = agent.execute_job({
            "method": "ping",
            "target": "example.com",
            "execution_deadline_monotonic": time.monotonic() + 14,
        })
        self.assertEqual(payload, {
            "status": "failed",
            "error": {"code": "resolution_changed", "message": "changed"},
        })

    def test_worker_exception_fallback_matches_api_shape(self):
        runner = object.__new__(agent.AgentRunner)
        future = concurrent_future = mock.Mock()
        concurrent_future.done.return_value = True
        concurrent_future.result.side_effect = RuntimeError("secret detail")
        runner.futures = {future: "12345678-abcd"}
        runner.delivery_state = {}
        runner.completion_deadlines = {}
        runner.client = mock.Mock()
        runner.complete_finished()
        runner.client.post.assert_called_once_with(
            "agent/jobs/12345678-abcd/complete",
            {
                "status": "failed",
                "error": {
                    "code": "agent_execution_failed",
                    "message": "Unhandled worker failure: RuntimeError",
                },
            },
            request_timeout=agent.COMPLETION_REQUEST_SECONDS,
        )

    def _delivery_runner(self, payload, side_effect):
        runner = object.__new__(agent.AgentRunner)
        future = agent.concurrent.futures.Future()
        future.set_result(payload)
        runner.futures = {future: "12345678-abcd"}
        runner.delivery_state = {}
        runner.completion_deadlines = {}
        runner.client = mock.Mock()
        runner.client.post.side_effect = side_effect
        return runner, future

    def test_first_completion_http_is_bounded_by_server_budget(self):
        payload = {"status": "failed", "error": {"code": "probe_failed", "message": "safe"}}
        runner, future = self._delivery_runner(payload, None)
        runner.completion_deadlines[future] = time.monotonic() + 0.5
        runner.complete_finished()
        request_timeout = runner.client.post.call_args.kwargs["request_timeout"]
        self.assertGreater(request_timeout, 0)
        self.assertLessEqual(request_timeout, 0.5)

    def test_transient_completion_failure_retries_from_memory_then_succeeds(self):
        payload = {
            "status": "completed",
            "resolved_addresses": ["1.1.1.1"],
            "resolution_fingerprint": "a" * 64,
            "result": {"output": ["sensitive.example output"]},
        }
        runner, future = self._delivery_runner(
            payload, [agent.AgentError("temporary network failure"), {"data": {"status": "completed"}}]
        )
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            runner.complete_finished()
            self.assertIn(future, runner.futures)
            self.assertEqual(runner.delivery_state[future][0], 1)
            runner.delivery_state[future] = (1, 0.0)
            runner.complete_finished()
        self.assertNotIn(future, runner.futures)
        self.assertEqual(runner.client.post.call_count, 2)
        self.assertNotIn("sensitive.example", stderr.getvalue())
        self.assertNotIn("1.1.1.1", stderr.getvalue())

    def test_http_4xx_completion_failure_is_terminal(self):
        runner, future = self._delivery_runner(
            {"status": "failed", "error": {"code": "probe_failed", "message": "safe"}},
            agent.ApiHttpError("agent/jobs/id/complete", 409),
        )
        with contextlib.redirect_stderr(io.StringIO()):
            runner.complete_finished()
        self.assertNotIn(future, runner.futures)
        self.assertEqual(runner.client.post.call_count, 1)

    def test_http_5xx_completion_retries_exactly_three_times(self):
        runner, future = self._delivery_runner(
            {"status": "failed", "error": {"code": "probe_failed", "message": "safe"}},
            agent.ApiHttpError("agent/jobs/id/complete", 503),
        )
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            for expected_attempt in range(1, agent.MAX_COMPLETION_ATTEMPTS + 1):
                runner.complete_finished()
                if future in runner.delivery_state:
                    attempts, _next_at = runner.delivery_state[future]
                    self.assertEqual(attempts, expected_attempt)
                    runner.delivery_state[future] = (attempts, 0.0)
        self.assertNotIn(future, runner.futures)
        self.assertEqual(runner.client.post.call_count, agent.MAX_COMPLETION_ATTEMPTS)
        self.assertIn("abandoned after 3 bounded attempts", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
