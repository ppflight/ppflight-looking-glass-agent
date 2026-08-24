#!/usr/bin/env python3
"""Safe local control console for the PPFlight Looking Glass agent."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import pathlib
import shutil
import subprocess
import sys
from typing import Any, Iterable

import agent


SERVICE_NAME = "ppflight-looking-glass.service"
APP_DIR = "/opt/ppflight-looking-glass"
NODE_FIELDS = (
    "id", "code", "name", "city", "country_code", "enabled", "public", "status", "last_seen_at"
)
STAT_FIELDS = (
    "total_24h",
    "probes_24h",
    "total_probes_24h",
    "probes_total_24h",
    "anonymous_visitor_fingerprint_count",
    "anonymous_visitor_fingerprints_24h",
    "unique_visitor_fingerprints_24h",
    "anonymous_visitors_24h",
    "unique_visitors_24h",
    "security_rejections_24h",
    "safety_rejections_24h",
    "rejections_24h",
    "active_ip_block_count",
)
STATUS_FIELDS = ("queued", "claimed", "completed", "failed", "expired")


def fixed_command(argv: list[str], timeout: int = 8) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            cwd="/",
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""
    output = completed.stdout[: 64 * 1024].decode("utf-8", errors="replace").strip()
    return completed.returncode, output


def service_property(name: str) -> str:
    systemctl = shutil.which("systemctl", path="/usr/bin:/bin")
    if not systemctl:
        return "unavailable"
    code, output = fixed_command(
        [systemctl, "show", SERVICE_NAME, f"--property={name}", "--value", "--no-pager"]
    )
    return output if code == 0 and output else "unknown"


def bound_identity(config: dict[str, Any]) -> tuple[bool, str]:
    try:
        state = agent.load_json_file(config["state_path"])
    except agent.AgentError:
        return False, "—"
    token = state.get("agent_token")
    bound = isinstance(token, str) and len(token) >= 20
    node_id = state.get("agent_uuid")
    return bound, str(node_id)[:80] if bound and node_id else "—"


def binary_status() -> dict[str, str]:
    return {
        binary: (agent.find_binary(binary) if shutil.which(binary, path="/usr/sbin:/usr/bin:/sbin:/bin") else "missing")
        for binary in ("ping", "traceroute", "mtr")
    }


def safe_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, str):
        return value.replace("\n", " ").replace("\r", " ")[:190]
    return "—"


def fetch_summary(config: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    try:
        state = agent.load_json_file(config["state_path"])
        token = state.get("agent_token")
        if not isinstance(token, str) or len(token) < 20:
            return "Agent is not bound.", None
        client = agent.ApiClient(config["api_base_url"], config["request_timeout_seconds"], token)
        response = agent.unwrap_data(client.post("agent/control/summary", {}))
        if not isinstance(response, dict):
            return "Control summary returned an invalid response.", None
        # Never return arbitrary server fields to presentation code.
        raw_node = response.get("node") if isinstance(response.get("node"), dict) else {}
        raw_stats = response.get("stats") if isinstance(response.get("stats"), dict) else {}
        node = {key: raw_node[key] for key in NODE_FIELDS if key in raw_node}
        stats = {
            key: raw_stats[key]
            for key in STAT_FIELDS
            if key in raw_stats
            and isinstance(raw_stats[key], int)
            and not isinstance(raw_stats[key], bool)
            and raw_stats[key] >= 0
        }
        raw_statuses = raw_stats.get("status_counts") or raw_stats.get("by_status")
        if isinstance(raw_statuses, dict):
            stats["status_counts"] = {
                key: raw_statuses[key]
                for key in STATUS_FIELDS
                if key in raw_statuses
                and isinstance(raw_statuses[key], int)
                and not isinstance(raw_statuses[key], bool)
                and raw_statuses[key] >= 0
            }
        return "Connected", {"node": node, "stats": stats}
    except agent.ApiHttpError as exc:
        if exc.status in (404, 405):
            return "Server control summary is not available yet; local status remains usable.", None
        return f"Server returned HTTP {exc.status}; no private response body was displayed.", None
    except agent.AgentError:
        return "Connection check failed; no visitor or probe data was displayed.", None


def print_header(config: dict[str, Any]) -> None:
    bound, node_id = bound_identity(config)
    print("PPFlight Looking Glass Agent")
    print("=" * 32)
    print(f"Service:       {service_property('ActiveState')} ({service_property('UnitFileState')})")
    print(f"Version:       {agent.VERSION}")
    print(f"Platform:      {agent.api_platform()} / {agent.api_architecture()}")
    print(f"Bound:         {'yes' if bound else 'no'}")
    print(f"Node ID:       {node_id}")
    print(f"ADMIN API:     {config['api_base_url']}")
    print(f"Service seen:  {service_property('ActiveEnterTimestamp')}")
    print("Safety limits: ping 5 · trace 20 hops · mtr 5 cycles · 15s · 64KiB · concurrency 4")
    print("Probe tools:")
    for binary, path in binary_status().items():
        print(f"  {binary:<11} {path}")


def print_summary(config: dict[str, Any]) -> bool:
    checked_at = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    message, summary = fetch_summary(config)
    print(f"Connection:    {message}")
    print(f"Checked at:    {checked_at}")
    if summary is None:
        return False
    print("ADMIN node:")
    for key in NODE_FIELDS:
        if key in summary["node"]:
            print(f"  {key:<38} {safe_scalar(summary['node'][key])}")
    print("Anonymous 24h statistics:")
    for key in STAT_FIELDS:
        if key in summary["stats"]:
            print(f"  {key:<38} {safe_scalar(summary['stats'][key])}")
    statuses = summary["stats"].get("status_counts")
    if isinstance(statuses, dict):
        for key in STATUS_FIELDS:
            if key in statuses:
                print(f"  status.{key:<31} {safe_scalar(statuses[key])}")
    return True


def print_log_diagnostics() -> None:
    journalctl = shutil.which("journalctl", path="/usr/bin:/bin")
    if not journalctl:
        print("journalctl is unavailable.")
        return
    code, output = fixed_command(
        [journalctl, "--unit", SERVICE_NAME, "--lines", "200", "--output", "json", "--no-pager"],
        timeout=10,
    )
    if code != 0:
        print("Journal diagnostics are unavailable.")
        return
    categories: collections.Counter[str] = collections.Counter()
    latest = "—"
    for raw_line in output.splitlines():
        try:
            record = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        message = record.get("MESSAGE") if isinstance(record.get("MESSAGE"), str) else ""
        priority = str(record.get("PRIORITY", "6"))
        timestamp = record.get("__REALTIME_TIMESTAMP")
        if isinstance(timestamp, str) and timestamp.isdigit():
            latest = dt.datetime.fromtimestamp(int(timestamp) / 1_000_000, dt.timezone.utc).isoformat()
        if "completion delivery failed" in message:
            categories["result delivery failures"] += 1
        elif "agent API error" in message:
            categories["API communication errors"] += 1
        elif "Started" in message or "Stopped" in message:
            categories["service lifecycle events"] += 1
        elif priority.isdigit() and int(priority) <= 4:
            categories["other warnings/errors"] += 1
        else:
            categories["informational entries"] += 1
    print("Journal diagnostic summary (raw messages intentionally hidden):")
    print(f"  entries scanned: {sum(categories.values())}")
    print(f"  latest entry:    {latest}")
    for category in (
        "API communication errors", "result delivery failures", "service lifecycle events",
        "other warnings/errors", "informational entries",
    ):
        print(f"  {category:<27} {categories[category]}")


def run_bind() -> int:
    bind_script = pathlib.Path(APP_DIR) / "bind.sh"
    if not bind_script.is_file():
        print("Installed bind.sh was not found.", file=sys.stderr)
        return 1
    return subprocess.run([str(bind_script)], shell=False, check=False).returncode


def interactive(config: dict[str, Any]) -> int:
    while True:
        print("\033[2J\033[H", end="")
        print_header(config)
        print()
        print_summary(config)
        print("\n[1] Refresh  [2] Connection summary  [3] Log diagnostics  [4] Bind/rebind  [0] Exit")
        choice = input("Select: ").strip()
        if choice == "0":
            return 0
        if choice == "1":
            continue
        if choice == "2":
            print_summary(config)
        elif choice == "3":
            print_log_diagnostics()
        elif choice == "4":
            print("Binding replaces local credentials only after the ADMIN one-time code succeeds.")
            run_bind()
        else:
            print("Unknown selection.")
        input("Press Enter to continue...")


def parse_arguments(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PPFlight Looking Glass Agent console")
    parser.add_argument("--config", default=agent.DEFAULT_CONFIG)
    parser.add_argument(
        "command", nargs="?", default="console",
        choices=("console", "status", "summary", "check", "logs", "bind", "version"),
    )
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    if arguments.command == "version":
        print(agent.VERSION)
        return 0
    try:
        config = agent.validate_config(agent.load_json_file(arguments.config))
    except agent.AgentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if arguments.command == "status":
        print_header(config)
        return 0
    if arguments.command == "summary":
        return 0 if print_summary(config) else 2
    if arguments.command == "check":
        print_header(config)
        print()
        return 0 if print_summary(config) else 2
    if arguments.command == "logs":
        print_log_diagnostics()
        return 0
    if arguments.command == "bind":
        return run_bind()
    if not sys.stdin.isatty():
        print("Interactive console requires a terminal. Use: ag status|summary|check|logs|bind|version")
        return 2
    return interactive(config)


if __name__ == "__main__":
    raise SystemExit(main())
