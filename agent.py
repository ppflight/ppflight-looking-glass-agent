#!/usr/bin/env python3
"""PPFlight Looking Glass agent.

The agent only makes outbound HTTPS requests. It never accepts inbound connections
and never executes server-provided command lines or command arguments.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import ipaddress
import json
import multiprocessing
import os
import pathlib
import platform
import re
import selectors
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Iterable


VERSION = "1.0.1"
DEFAULT_CONFIG = "/etc/ppflight-looking-glass/config.json"
DEFAULT_STATE = "/var/lib/ppflight-looking-glass/state.json"
ALLOWED_METHODS = frozenset({"ping", "trace", "mtr"})
MAX_OUTPUT_BYTES = 64 * 1024
MAX_CONCURRENCY = 4
MAX_TASK_SECONDS = 15
MAX_COMPLETION_ATTEMPTS = 3
COMPLETION_REQUEST_SECONDS = 2
COMPLETION_BACKOFF_SECONDS = (0.25, 0.75)
COMPLETION_TRANSPORT_RESERVE_SECONDS = 1.0
OUTPUT_TRUNCATION_SUFFIX = b"\n[output truncated by PPFlight agent]\n"
METADATA_IPS = frozenset(
    {
        "169.254.169.254",  # AWS, GCP, Azure and others
        "169.254.170.2",    # AWS ECS
        "100.100.100.200",  # Alibaba Cloud
        "100.100.100.201",
    }
)
BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
        "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
        "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
        "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64",
        "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
    )
)
METADATA_NAMES = frozenset(
    {
        "metadata.google.internal",
        "metadata.google",
        "instance-data",
        "instance-data.ec2.internal",
    }
)
DOMAIN_RE = re.compile(
    r"(?=^.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])"
)


class AgentError(RuntimeError):
    """Expected, reportable agent error."""


class ApiHttpError(AgentError):
    """An API request returned a non-success HTTP status."""

    def __init__(self, path: str, status: int) -> None:
        self.path = path
        self.status = status
        super().__init__(f"API returned HTTP {status} for {path}")


class TargetRejected(AgentError):
    """The requested target is not safe to probe."""


class ResolutionChanged(TargetRejected):
    """DNS no longer matches the resolution approved by the WWW API."""


class TaskDeadlineExceeded(AgentError):
    """The complete validation and probe deadline was exhausted."""


@dataclass(frozen=True)
class ResolvedTarget:
    requested: str
    addresses: tuple[str, ...]

    @property
    def pinned_ip(self) -> str:
        # Prefer IPv4 for consistent output, while retaining IPv6-only support.
        return sorted(self.addresses, key=lambda item: (":" in item, item))[0]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_json_file(path: str) -> dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = json.load(handle)
    except FileNotFoundError as exc:
        raise AgentError(f"Required file does not exist: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise AgentError(f"Cannot read valid JSON from {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise AgentError(f"Expected a JSON object in {path}")
    return value


def atomic_write_json(path: str, value: dict[str, Any], mode: int = 0o600) -> None:
    destination = pathlib.Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def validate_config(config: dict[str, Any]) -> dict[str, Any]:
    result = dict(config)
    raw_base = str(result.get("api_base_url", "")).rstrip("/")
    parsed = urllib.parse.urlsplit(raw_base)
    if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment:
        raise AgentError("api_base_url must be an HTTPS URL without query or fragment")
    if parsed.username or parsed.password:
        raise AgentError("api_base_url must not contain credentials")
    result["api_base_url"] = raw_base
    result["agent_name"] = str(result.get("agent_name", socket.gethostname())).strip()
    result["location"] = str(result.get("location", "unknown")).strip()
    if not result["agent_name"] or len(result["agent_name"]) > 100:
        raise AgentError("agent_name must contain 1 to 100 characters")
    poll = int(result.get("poll_interval_seconds", 2))
    heartbeat = int(result.get("heartbeat_interval_seconds", 30))
    request_timeout = int(result.get("request_timeout_seconds", 10))
    if not 1 <= poll <= 30:
        raise AgentError("poll_interval_seconds must be between 1 and 30")
    if not 10 <= heartbeat <= 300:
        raise AgentError("heartbeat_interval_seconds must be between 10 and 300")
    if not 2 <= request_timeout <= 15:
        raise AgentError("request_timeout_seconds must be between 2 and 15")
    result["poll_interval_seconds"] = poll
    result["heartbeat_interval_seconds"] = heartbeat
    result["request_timeout_seconds"] = request_timeout
    result["state_path"] = str(result.get("state_path", DEFAULT_STATE))
    return result


def normalize_target(raw_target: Any) -> str:
    if not isinstance(raw_target, str):
        raise TargetRejected("Target must be a domain name or IP address")
    target = raw_target.strip()
    if not target or len(target) > 253:
        raise TargetRejected("Target length is invalid")
    if any(char.isspace() for char in target):
        raise TargetRejected("Target must not contain whitespace")
    # URL, port, path, zone identifier and shell-like inputs are all invalid.
    if any(char in target for char in ("/", "\\", "@", "?", "#", "%", "[", "]")):
        raise TargetRejected("URLs, ports and command parameters are not allowed")

    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass

    if ":" in target:
        raise TargetRejected("Ports and invalid IPv6 addresses are not allowed")
    ascii_target = target.rstrip(".")
    try:
        ascii_target = ascii_target.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise TargetRejected("Domain name is invalid") from exc
    if not DOMAIN_RE.fullmatch(ascii_target) or ascii_target in METADATA_NAMES:
        raise TargetRejected("Domain name is invalid or prohibited")
    return ascii_target


def is_public_address(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return (
        parsed.is_global
        and not parsed.is_private
        and not parsed.is_loopback
        and not parsed.is_link_local
        and not parsed.is_multicast
        and not parsed.is_reserved
        and not parsed.is_unspecified
        and not any(parsed.version == network.version and parsed in network for network in BLOCKED_NETWORKS)
        and str(parsed) not in METADATA_IPS
    )


def _getaddrinfo_worker(target: str, sender: Any) -> None:
    """Resolve in an isolated process so a stuck libc resolver can be killed."""
    try:
        answers = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
        addresses = list(dict.fromkeys(answer[4][0] for answer in answers))
        if len(addresses) > 16:
            sender.send(("too_many", []))
        else:
            sender.send(("ok", addresses))
    except socket.gaierror:
        sender.send(("gaierror", []))
    except BaseException:
        # Never serialize exception details from libc/platform internals.
        sender.send(("error", []))
    finally:
        sender.close()


def _stop_resolution_process(process: Any) -> None:
    if not process.is_alive():
        process.join(timeout=0)
        return
    process.terminate()
    process.join(timeout=0.25)
    if process.is_alive():
        process.kill()
        process.join(timeout=0.25)


def _resolve_hostname_with_deadline(target: str, deadline: float) -> tuple[str, ...]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TaskDeadlineExceeded("Task deadline expired during DNS resolution")

    # ``spawn`` is safe when the Agent's four jobs are running in worker threads;
    # unlike ``fork``, it does not clone locks held by another thread.
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_getaddrinfo_worker, args=(target, sender))
    process.daemon = True
    try:
        process.start()
        sender.close()
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not receiver.poll(remaining):
            raise TaskDeadlineExceeded("Task deadline expired during DNS resolution")
        try:
            status, raw_addresses = receiver.recv()
        except EOFError as exc:
            raise TargetRejected("Domain name could not be resolved") from exc
        if status == "gaierror":
            raise TargetRejected("Domain name could not be resolved")
        if status == "too_many":
            raise TargetRejected("Domain name returned too many addresses")
        if status != "ok" or not isinstance(raw_addresses, list):
            raise TargetRejected("Domain name resolution failed safely")
        return tuple(str(address) for address in raw_addresses)
    finally:
        receiver.close()
        sender.close()
        if process.pid is not None:
            _stop_resolution_process(process)


def resolve_public_target(
    raw_target: Any, deadline: float | None = None
) -> ResolvedTarget:
    target = normalize_target(raw_target)
    try:
        literal = ipaddress.ip_address(target)
    except ValueError:
        literal = None

    if literal is not None:
        address = str(literal)
        if not is_public_address(address):
            raise TargetRejected("Private, local, reserved and metadata addresses are prohibited")
        return ResolvedTarget(target, (address,))

    effective_deadline = deadline if deadline is not None else time.monotonic() + MAX_TASK_SECONDS
    addresses = tuple(dict.fromkeys(_resolve_hostname_with_deadline(target, effective_deadline)))
    if not addresses:
        raise TargetRejected("Domain name returned no addresses")
    if any(not is_public_address(address) for address in addresses):
        raise TargetRejected("Every domain answer must be a public address")
    return ResolvedTarget(target, addresses)


def resolve_and_pin(raw_target: Any, deadline: float | None = None) -> ResolvedTarget:
    effective_deadline = deadline if deadline is not None else time.monotonic() + MAX_TASK_SECONDS
    first = resolve_public_target(raw_target, deadline=effective_deadline)
    if len(first.addresses) == 1 and first.requested == first.addresses[0]:
        return first
    # Re-resolve immediately before execution and reject changes. The command is
    # then given the selected literal IP, not the hostname, preventing rebinding.
    second = resolve_public_target(first.requested, deadline=effective_deadline)
    if set(first.addresses) != set(second.addresses):
        raise TargetRejected("DNS answers changed during validation; task rejected")
    return second


def find_binary(name: str) -> str:
    binary = shutil.which(name, path="/usr/sbin:/usr/bin:/sbin:/bin")
    if not binary:
        raise AgentError(f"Required probe binary is unavailable: {name}")
    return binary


def build_command(method: str, pinned_ip: str) -> list[str]:
    if method not in ALLOWED_METHODS:
        raise AgentError("Unsupported probe tool")
    version_flag = "-6" if ipaddress.ip_address(pinned_ip).version == 6 else "-4"
    if method == "ping":
        return [find_binary("ping"), version_flag, "-n", "-c", "5", "-W", "2", pinned_ip]
    if method == "trace":
        return [
            find_binary("traceroute"),
            version_flag,
            "-n",
            "-m",
            "20",
            "-w",
            "1",
            "-q",
            "1",
            pinned_ip,
        ]
    return [
        find_binary("mtr"),
        version_flag,
        "--report",
        "--no-dns",
        "--report-cycles",
        "5",
        "--interval",
        "1.0",
        "--max-ttl",
        "20",
        pinned_ip,
    ]


def truncate_utf8(
    raw: bytes, maximum: int = MAX_OUTPUT_BYTES, force_truncated: bool = False
) -> tuple[str, bool]:
    truncated = force_truncated or len(raw) > maximum
    if truncated:
        raw = raw[: max(0, maximum - len(OUTPUT_TRUNCATION_SUFFIX))] + OUTPUT_TRUNCATION_SUFFIX
    return raw.decode("utf-8", errors="replace"), truncated


def _redact_match(match: re.Match[str]) -> str:
    candidate = match.group(0)
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return candidate
    return candidate if is_public_address(str(address)) else "private hop"


def redact_non_public_hops(output: str) -> str:
    output = IPV4_RE.sub(_redact_match, output)
    return IPV6_RE.sub(_redact_match, output)


def _utf8_chunks(value: str, maximum_bytes: int = 1024) -> list[str]:
    chunks: list[str] = []
    current: list[str] = []
    current_bytes = 0
    for character in value:
        encoded_length = len(character.encode("utf-8"))
        if current and current_bytes + encoded_length > maximum_bytes:
            chunks.append("".join(current))
            current = []
            current_bytes = 0
        current.append(character)
        current_bytes += encoded_length
    if current or not chunks:
        chunks.append("".join(current))
    return chunks


def output_lines(output: str) -> list[str]:
    """Return a Laravel-compatible output array bounded by lines and JSON bytes."""
    candidates: list[str] = []
    for line in redact_non_public_hops(output).splitlines() or [""]:
        candidates.extend(_utf8_chunks(line))
        if len(candidates) >= 256:
            candidates = candidates[:256]
            break

    accepted: list[str] = []
    for line in candidates:
        proposed = accepted + [line]
        encoded = json.dumps(
            {"output": proposed}, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        # Reserve space for the server-approved summary and JSON envelope.
        if len(encoded) > MAX_OUTPUT_BYTES - 2048:
            break
        accepted = proposed
    return accepted


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_fixed_command(
    argv: list[str], timeout: int | float = MAX_TASK_SECONDS
) -> dict[str, Any]:
    started = time.monotonic()
    deadline = started + max(0.0, float(timeout))
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=False,
        cwd="/",
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
        start_new_session=True,
    )
    timed_out = False
    truncated = False
    raw_output = bytearray()
    capture_limit = MAX_OUTPUT_BYTES - len(OUTPUT_TRUNCATION_SUFFIX)
    selector = selectors.DefaultSelector()
    try:
        if process.stdout is None:  # pragma: no cover - guaranteed by Popen arguments
            raise AgentError("Probe output pipe is unavailable")
        descriptor = process.stdout.fileno()
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _kill_process_group(process)
                break
            events = selector.select(remaining)
            if not events:
                timed_out = True
                _kill_process_group(process)
                break
            available = capture_limit - len(raw_output)
            if available <= 0:
                truncated = True
                _kill_process_group(process)
                break
            try:
                chunk = os.read(descriptor, min(8192, available))
            except BlockingIOError:
                continue
            if chunk:
                raw_output.extend(chunk)
                if len(raw_output) >= capture_limit:
                    truncated = True
                    _kill_process_group(process)
                    break
                continue

            selector.unregister(descriptor)
            try:
                process.wait(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_process_group(process)
            break
    finally:
        selector.close()
        if process.poll() is None:
            _kill_process_group(process)
        try:
            process.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            # A killed process stuck in an uninterruptible kernel state must not
            # retain one of the Agent's four worker slots indefinitely.
            pass
        if process.stdout is not None:
            process.stdout.close()
    text, truncated = truncate_utf8(bytes(raw_output), force_truncated=truncated)
    return {
        "exit_code": process.returncode if process.returncode is not None else -signal.SIGKILL,
        "timed_out": timed_out,
        "truncated": truncated,
        "duration_ms": round((time.monotonic() - started) * 1000),
        "output": text,
    }


class ApiClient:
    def __init__(self, base_url: str, timeout: int, token: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.token = token
        self.ssl_context = ssl.create_default_context()
        self.opener = urllib.request.build_opener(
            _NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=self.ssl_context),
        )

    def post(
        self,
        path: str,
        payload: dict[str, Any],
        authenticated: bool = True,
        request_timeout: int | float | None = None,
    ) -> Any:
        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "User-Agent": f"PPFlight-Looking-Glass-Agent/{VERSION}",
        }
        if authenticated:
            if not self.token:
                raise AgentError("Agent is not bound")
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(
            url,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            timeout = self.timeout if request_timeout is None else request_timeout
            with self.opener.open(request, timeout=timeout) as response:
                body = response.read(1024 * 1024 + 1)
                if len(body) > 1024 * 1024:
                    raise AgentError("API response is too large")
                if not body:
                    return None
                return json.loads(body.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            # Do not include response bodies: they can contain secrets or visitor data.
            raise ApiHttpError(path, exc.code) from exc
        except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
            raise AgentError(f"API request failed for {path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise AgentError(f"API returned invalid JSON for {path}") from exc


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never forward binding codes or bearer tokens through HTTP redirects."""

    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


def unwrap_data(value: Any) -> Any:
    if isinstance(value, dict) and "data" in value:
        return value["data"]
    return value


def extract_token(response: Any) -> tuple[str, str | None]:
    value = unwrap_data(response)
    if not isinstance(value, dict):
        raise AgentError("Bind response did not contain an object")
    token = value.get("agent_token") or value.get("token")
    if not isinstance(token, str) or len(token) < 20:
        raise AgentError("Bind response did not contain a valid agent token")
    node = value.get("node") if isinstance(value.get("node"), dict) else {}
    agent_uuid = value.get("agent_uuid") or value.get("uuid") or value.get("id") or node.get("id")
    return token, str(agent_uuid) if agent_uuid is not None else None


def capabilities() -> dict[str, Any]:
    return {
        "methods": sorted(ALLOWED_METHODS),
    }


def distribution_id() -> str:
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("ID="):
                    return line.partition("=")[2].strip().strip("\"'")[:50]
    except OSError:
        pass
    return "unknown"


def api_platform() -> str:
    distribution = distribution_id()
    return distribution if distribution in {
        "debian", "ubuntu", "centos", "rocky", "almalinux", "rhel", "fedora"
    } else "linux"


def api_architecture() -> str:
    architecture = platform.machine().lower()
    aliases = {"x86_64": "x86_64", "amd64": "amd64", "aarch64": "aarch64", "arm64": "arm64"}
    return aliases.get(architecture, architecture)


def api_hostname() -> str:
    hostname = re.sub(r"[^A-Za-z0-9.-]+", "-", socket.gethostname()).strip(".-")
    return (hostname or "looking-glass-agent")[:190]


def identity_payload(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "hostname": api_hostname(),
        "agent_version": VERSION,
        "platform": api_platform(),
        "architecture": api_architecture(),
        "capabilities": capabilities(),
    }


def bind_agent(config: dict[str, Any], binding_code: str) -> None:
    code = binding_code.strip()
    if not code or len(code) > 200:
        raise AgentError("Binding code is invalid")
    client = ApiClient(config["api_base_url"], config["request_timeout_seconds"])
    payload = identity_payload(config)
    payload["binding_code"] = code
    response = client.post("agents/bind", payload, authenticated=False)
    token, agent_uuid = extract_token(response)
    atomic_write_json(
        config["state_path"],
        {"agent_token": token, "agent_uuid": agent_uuid, "bound_at": utc_now()},
    )


def _parse_server_deadline(raw_deadline: Any) -> dt.datetime:
    if not isinstance(raw_deadline, str) or not 1 <= len(raw_deadline) <= 64:
        raise AgentError("Claimed job deadline is invalid")
    normalized = raw_deadline[:-1] + "+00:00" if raw_deadline.endswith("Z") else raw_deadline
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise AgentError("Claimed job deadline is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AgentError("Claimed job deadline must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def normalize_job(
    response: Any, claim_started_monotonic: float | None = None
) -> dict[str, Any] | None:
    value = unwrap_data(response)
    if value in (None, {}, []):
        return None
    if isinstance(value, dict) and "job" in value:
        value = value["job"]
    if value is None:
        return None
    if not isinstance(value, dict):
        raise AgentError("Claim response did not contain a job object")
    job_uuid = value.get("uuid") or value.get("job_uuid") or value.get("id")
    method = value.get("method") or value.get("tool") or value.get("probe_type") or value.get("type")
    target = value.get("target")
    if not isinstance(job_uuid, str) or not re.fullmatch(r"[A-Za-z0-9-]{8,80}", job_uuid):
        raise AgentError("Claimed job UUID is invalid")
    if method not in ALLOWED_METHODS:
        raise AgentError("Claimed job method is not allowed")
    if not isinstance(target, str):
        raise AgentError("Claimed job target is invalid")
    contract = value.get("execution_contract")
    if not isinstance(contract, dict) or contract.get("version") != 1:
        raise AgentError("Claimed job execution contract is invalid")
    timeout_seconds = contract.get("timeout_seconds")
    if type(timeout_seconds) is not int or not 2 <= timeout_seconds <= MAX_TASK_SECONDS:
        raise AgentError("Claimed job timeout contract is invalid")
    server_deadline = _parse_server_deadline(value.get("deadline_at"))
    budget_started = (
        claim_started_monotonic
        if claim_started_monotonic is not None
        else time.monotonic()
    )
    completion_deadline = budget_started + float(timeout_seconds)
    execution_deadline = completion_deadline - COMPLETION_TRANSPORT_RESERVE_SECONDS
    addresses = value.get("resolved_addresses")
    fingerprint = value.get("resolution_fingerprint")
    if not isinstance(addresses, list) or not 1 <= len(addresses) <= 16:
        raise AgentError("Claimed job resolution is invalid")
    normalized_addresses: list[str] = []
    canonical_addresses: list[str] = []
    for address in addresses:
        if not isinstance(address, str) or not is_public_address(address):
            raise AgentError("Claimed job contains a prohibited resolved address")
        normalized_addresses.append(address.lower())
        canonical_addresses.append(str(ipaddress.ip_address(address)).lower())
    normalized_addresses = sorted(set(normalized_addresses))
    canonical_addresses = sorted(set(canonical_addresses))
    expected_fingerprint = hashlib.sha256("\n".join(normalized_addresses).encode("utf-8")).hexdigest()
    if not isinstance(fingerprint, str) or not re.fullmatch(r"[a-f0-9]{64}", fingerprint):
        raise AgentError("Claimed job resolution fingerprint is invalid")
    if not hmac_compare(fingerprint, expected_fingerprint):
        raise AgentError("Claimed job resolution proof does not match its addresses")
    return {
        "uuid": job_uuid,
        "method": method,
        "target": target,
        "resolved_addresses": normalized_addresses,
        "canonical_addresses": canonical_addresses,
        "resolution_fingerprint": fingerprint,
        # The wall-clock value is validated for protocol integrity but is not
        # compared with the node clock. Local monotonic budgeting avoids false
        # expiry when the Agent and WWW clocks differ.
        "server_deadline_at": server_deadline.isoformat().replace("+00:00", "Z"),
        "completion_deadline_monotonic": completion_deadline,
        "execution_deadline_monotonic": execution_deadline,
    }


def hmac_compare(left: str, right: str) -> bool:
    # compare_digest is exposed by hmac; importing locally keeps the module surface small.
    import hmac

    return hmac.compare_digest(left, right)


def execute_job(job: dict[str, Any]) -> dict[str, Any]:
    try:
        deadline = job.get("execution_deadline_monotonic")
        if not isinstance(deadline, (int, float)) or isinstance(deadline, bool):
            raise AgentError("Claimed job local deadline is invalid")
        resolved = resolve_and_pin(job["target"], deadline=deadline)
        execution_addresses = sorted(
            set(str(ipaddress.ip_address(address)).lower() for address in resolved.addresses)
        )
        if execution_addresses != job["canonical_addresses"]:
            raise ResolutionChanged("DNS resolution changed before execution")
        # Canonical address equality proves the execution-time resolution still
        # represents the server-approved set. Return the server's exact spelling
        # and fingerprint because expanded IPv6 text has multiple valid forms.
        fingerprint = job["resolution_fingerprint"]
        argv = build_command(job["method"], resolved.pinned_ip)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TaskDeadlineExceeded("Task deadline expired before probe execution")
        result = run_fixed_command(argv, timeout=remaining)
        successful = result["exit_code"] == 0 and not result["timed_out"]
        if successful:
            return {
                "status": "completed",
                "resolved_addresses": job["resolved_addresses"],
                "resolution_fingerprint": fingerprint,
                "result": {
                    "output": output_lines(result["output"]),
                    "summary": {
                        "exit_code": result["exit_code"],
                        "duration_ms": result["duration_ms"],
                        "timed_out": result["timed_out"],
                        "truncated": result["truncated"],
                    },
                },
            }
        code = "execution_timeout" if result["timed_out"] else "probe_failed"
        return {
            "status": "failed",
            "error": {"code": code, "message": "The network probe did not complete successfully."},
        }
    except (AgentError, OSError, ValueError) as exc:
        if isinstance(exc, TaskDeadlineExceeded):
            code = "execution_timeout"
        elif isinstance(exc, ResolutionChanged):
            code = "resolution_changed"
        elif isinstance(exc, TargetRejected):
            code = "unsafe_target"
        else:
            code = "agent_execution_failed"
        return {
            "status": "failed",
            "error": {"code": code, "message": str(exc)[:500]},
        }


class AgentRunner:
    def __init__(self, config: dict[str, Any], state: dict[str, Any]) -> None:
        token = state.get("agent_token")
        if not isinstance(token, str) or len(token) < 20:
            raise AgentError("Agent state does not contain a valid token; bind first")
        self.config = config
        self.state = state
        self.client = ApiClient(config["api_base_url"], config["request_timeout_seconds"], token)
        self.stop_event = threading.Event()
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_CONCURRENCY, thread_name_prefix="ppflight-lg"
        )
        self.futures: dict[concurrent.futures.Future[dict[str, Any]], str] = {}
        # Delivery state and Future results remain memory-only. Since undelivered
        # completions stay in `futures`, they occupy one of the four fixed slots
        # and cannot create an unbounded queue while the API is unavailable.
        self.delivery_state: dict[
            concurrent.futures.Future[dict[str, Any]], tuple[int, float]
        ] = {}
        self.completion_deadlines: dict[
            concurrent.futures.Future[dict[str, Any]], float
        ] = {}
        self.work_event = threading.Event()
        self.last_heartbeat = 0.0

    def stop(self, *_args: Any) -> None:
        self.stop_event.set()
        self.work_event.set()

    def heartbeat(self) -> None:
        now = time.monotonic()
        if now - self.last_heartbeat < self.config["heartbeat_interval_seconds"]:
            return
        self.client.post("agent/heartbeat", identity_payload(self.config))
        self.last_heartbeat = now

    def claim(self) -> bool:
        claim_started = time.monotonic()
        response = self.client.post(
            "agent/jobs/claim",
            {},
        )
        job = normalize_job(response, claim_started_monotonic=claim_started)
        if job is None:
            return False
        future = self.executor.submit(execute_job, job)
        self.futures[future] = job["uuid"]
        self.completion_deadlines[future] = job["completion_deadline_monotonic"]
        future.add_done_callback(lambda _future: self.work_event.set())
        return True

    def complete_finished(self) -> None:
        now = time.monotonic()
        for future in list(self.futures):
            if not future.done():
                continue
            attempts, next_attempt_at = self.delivery_state.get(future, (0, 0.0))
            if now < next_attempt_at:
                continue
            job_uuid = self.futures[future]
            completion_deadline = getattr(self, "completion_deadlines", {}).get(future)
            if completion_deadline is None:
                completion_timeout = float(COMPLETION_REQUEST_SECONDS)
            else:
                remaining_delivery = completion_deadline - time.monotonic()
                if remaining_delivery <= 0:
                    print("completion delivery skipped after local deadline", file=sys.stderr)
                    self._forget_completion(future)
                    continue
                completion_timeout = min(
                    float(COMPLETION_REQUEST_SECONDS), remaining_delivery
                )
            try:
                result = future.result()
            except Exception as exc:  # defensive containment around worker threads
                result = {
                    "status": "failed",
                    "error": {
                        "code": "agent_execution_failed",
                        "message": f"Unhandled worker failure: {type(exc).__name__}",
                    },
                }
            try:
                self.client.post(
                    f"agent/jobs/{job_uuid}/complete",
                    result,
                    request_timeout=completion_timeout,
                )
            except ApiHttpError as exc:
                if 400 <= exc.status < 500:
                    print(
                        f"completion delivery stopped after terminal HTTP {exc.status}",
                        file=sys.stderr,
                    )
                    self._forget_completion(future)
                    continue
                self._schedule_completion_retry(future, attempts, f"HTTP {exc.status}")
            except AgentError:
                self._schedule_completion_retry(future, attempts, "network/API failure")
            else:
                self._forget_completion(future)

    def _schedule_completion_retry(
        self,
        future: concurrent.futures.Future[dict[str, Any]],
        previous_attempts: int,
        reason: str,
    ) -> None:
        attempts = previous_attempts + 1
        if attempts >= MAX_COMPLETION_ATTEMPTS:
            print(
                f"completion delivery abandoned after {MAX_COMPLETION_ATTEMPTS} bounded attempts ({reason})",
                file=sys.stderr,
            )
            self._forget_completion(future)
            return
        delay = COMPLETION_BACKOFF_SECONDS[attempts - 1]
        self.delivery_state[future] = (attempts, time.monotonic() + delay)
        print(
            f"completion delivery retry {attempts + 1}/{MAX_COMPLETION_ATTEMPTS} scheduled ({reason})",
            file=sys.stderr,
        )

    def _forget_completion(
        self, future: concurrent.futures.Future[dict[str, Any]]
    ) -> None:
        self.futures.pop(future, None)
        self.delivery_state.pop(future, None)
        getattr(self, "completion_deadlines", {}).pop(future, None)

    def run(self, once: bool = False) -> None:
        try:
            while not self.stop_event.is_set():
                self.complete_finished()
                try:
                    self.heartbeat()
                    while len(self.futures) < MAX_CONCURRENCY and not self.stop_event.is_set():
                        if not self.claim():
                            break
                        # Do not continue issuing claim requests after a worker
                        # has finished; deliver that completion while its
                        # reserved transport second is still available.
                        self.complete_finished()
                        if self.work_event.is_set():
                            break
                except AgentError as exc:
                    print(f"agent API error: {exc}", file=sys.stderr)
                if once:
                    break
                wait_seconds = float(self.config["poll_interval_seconds"])
                if self.delivery_state:
                    next_delivery = min(state[1] for state in self.delivery_state.values())
                    wait_seconds = min(wait_seconds, max(0.05, next_delivery - time.monotonic()))
                self.work_event.wait(wait_seconds)
                self.work_event.clear()
        finally:
            self.executor.shutdown(wait=True, cancel_futures=False)
            self.complete_finished()


def parse_arguments(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PPFlight Looking Glass agent")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="Path to agent config JSON")
    subparsers = parser.add_subparsers(dest="command", required=True)
    bind = subparsers.add_parser("bind", help="Bind this agent with a one-time code")
    code_source = bind.add_mutually_exclusive_group(required=True)
    code_source.add_argument(
        "--code",
        help="One-time code (prefer --code-stdin to avoid process-list exposure)",
    )
    code_source.add_argument(
        "--code-stdin",
        action="store_true",
        help="Read the one-time binding code from standard input",
    )
    run = subparsers.add_parser("run", help="Run the agent polling loop")
    run.add_argument("--once", action="store_true", help="Run one polling pass for diagnostics")
    subparsers.add_parser("check", help="Validate config and installed probe commands")
    subparsers.add_parser("version", help="Print agent version")
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    if arguments.command == "version":
        print(VERSION)
        return 0
    try:
        config = validate_config(load_json_file(arguments.config))
        if arguments.command == "check":
            for binary in ("ping", "traceroute", "mtr"):
                find_binary(binary)
            print("Configuration and probe binaries are valid.")
            return 0
        if arguments.command == "bind":
            binding_code = sys.stdin.readline() if arguments.code_stdin else arguments.code
            bind_agent(config, binding_code)
            print("Agent bound successfully. The one-time code was not stored.")
            return 0
        state = load_json_file(config["state_path"])
        runner = AgentRunner(config, state)
        signal.signal(signal.SIGTERM, runner.stop)
        signal.signal(signal.SIGINT, runner.stop)
        runner.run(once=arguments.once)
        return 0
    except AgentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
