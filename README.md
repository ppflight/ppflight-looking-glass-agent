# PPFlight Looking Glass Agent

The PPFlight Looking Glass Agent runs network probes in a PPFlight region. It
accepts no inbound connections: it binds once with an ADMIN-generated code, then
uses outbound HTTPS to send heartbeats, claim jobs and return sanitized results.

The agent is intended for an isolated, low-privilege VM in the same region as the
network being measured. Do **not** install it on a Proxmox management host when a
small dedicated VM is available.

## Supported systems

- Debian and Ubuntu (`apt`)
- RHEL, Rocky Linux, AlmaLinux and CentOS Stream (`dnf`)
- Older CentOS installations exposing required packages through `yum`
- systemd and Python 3.9 or newer

The installer selects `apt`, `dnf` or `yum` and installs Python, `ping`,
`traceroute`, `mtr` and CA certificates. On RHEL-family systems it attempts to
install Python 3.9 when the default Python is older.

## GitHub installation

After this directory has been published as a repository:

```bash
git clone https://github.com/PPFlight/looking-glass-agent.git
cd looking-glass-agent
sudo ./install.sh
```

`install.sh` safely prompts for the one-time binding code at the end. Input is
hidden and is piped to the agent over standard input, so it is not stored in shell
history or exposed as a command-line argument.

For unattended installation, save only the one-time code in a root-readable file:

```bash
chmod 600 /root/ppflight-lg-binding-code
sudo ./install.sh --bind-code-file /root/ppflight-lg-binding-code
rm -f /root/ppflight-lg-binding-code
```

To install without binding or starting the service:

```bash
sudo ./install.sh --non-interactive
sudo nano /etc/ppflight-looking-glass/config.json
sudo /opt/ppflight-looking-glass/bind.sh
```

The repository itself contains no token, secret or binding code. Binding stores
the resulting agent token as `/var/lib/ppflight-looking-glass/state.json`, mode
`0600`, owned by the non-root `ppflight-lg` account.

## Configuration

The installer copies `config.example.json` to:

```text
/etc/ppflight-looking-glass/config.json
```

The production API URL is preconfigured. `agent_name` and `location` deliberately
default to `unconfigured` and are only local informational placeholders. The
one-time binding code determines the real ADMIN node identity, code, region and
public visibility; an Agent cannot choose or overwrite those properties. Supported
values for polling and request timeouts are deliberately bounded by the agent.

Validate an installation without making an API request:

```bash
sudo -u ppflight-lg /opt/ppflight-looking-glass/python3 \
  /opt/ppflight-looking-glass/agent.py \
  --config /etc/ppflight-looking-glass/config.json check
```

Service diagnostics:

```bash
ag
```

The installer adds `/usr/local/bin/ag`. Running `ag` opens an interactive Agent
console showing service state, version/platform, binding state, node ID, API base,
connection check, probe binaries and immutable safety ceilings. It never displays
the bearer token, visitor IP hashes, targets, probe output or raw journal messages.

Non-interactive commands are also available:

```bash
ag status     # local service, binding and safety status
ag summary    # safe ADMIN node and anonymous 24-hour counters
ag check      # local status plus API connection summary
ag logs       # categorized journal counts; raw messages remain hidden
ag bind       # securely bind or rebind with a one-time ADMIN code
ag version
```

`ag summary` uses `POST /agent/control/summary`. Only a fixed allowlist from
`data.node` and `data.stats` is rendered: aggregate 24-hour totals, known status
counts, anonymous visitor-fingerprint count and security-rejection count. If an
older WWW deployment does not provide the endpoint, the console reports that
cleanly and keeps all local status commands usable.

The console may also display `active_ip_block_count`, which is only an aggregate
number. Exact blocked IP addresses are restricted to PPFlight Super Admin and are
never sent to, stored by, or displayed on an Agent node.

## API contract

All requests and responses are JSON and use `Cache-Control: no-store`. The agent
uses these fixed endpoints beneath `api_base_url`:

| Purpose | Method and path | Authentication |
| --- | --- | --- |
| One-time bind | `POST /agents/bind` | `binding_code` in JSON |
| Heartbeat | `POST /agent/heartbeat` | Bearer agent token |
| Claim work | `POST /agent/jobs/claim` | Bearer agent token |
| Complete work | `POST /agent/jobs/{uuid}/complete` | Bearer agent token |
| Safe console summary | `POST /agent/control/summary` | Bearer agent token |

The bind response contains `agent_token` and `node.id`. A claimed job contains
`id`, `method`, `target`, `resolved_addresses`, `resolution_fingerprint` and its
execution contract. API methods are `ping`, `trace` and `mtr`; `trace` is executed
locally with the `traceroute` binary. Any arguments supplied by the server are
ignored; commands are constructed from fixed local argument arrays. Successful
completion sends `status: completed`, the verified resolution proof and
`result.output` as a bounded string array. Failures send `status: failed` with a
structured error code and message.

## Security boundaries

The agent enforces the following independently from the WWW API:

- target must be exactly one domain, IPv4 address or IPv6 address;
- URLs, ports, paths, zone identifiers and command parameters are rejected;
- loopback, private, link-local, multicast, reserved and metadata addresses are
  rejected;
- every DNS answer must be public; DNS is resolved twice in killable isolated
  resolver processes immediately before the probe, both answer sets must match,
  and the command receives only the pinned IP;
- subprocesses always use `shell=False`, a fixed environment and fixed argv;
- ping is fixed at 5 packets, trace at 20 hops, and MTR at 5 cycles/20 hops
  (below the 10-cycle security ceiling) with a non-root-safe 1-second interval;
- the claim HTTP round trip, DNS validation and probe share the server contract's
  15-second monotonic budget; execution stops about one second early to reserve
  first-completion transport time, while the server's `deadline_at` is validated
  but not compared to the node wall clock (avoiding clock-skew false expiry);
- stdout and stderr are captured incrementally with a hard 64 KiB memory ceiling;
  the process group is killed as soon as that ceiling is reached, and non-public
  hops in the bounded result are replaced with `private hop`;
- no more than four jobs run concurrently;
- results and visitor targets are never queued or persisted on agent disk.

Completion delivery is reliability-bounded: a network error or HTTP 5xx response
is retried from memory up to three times with short backoff and a two-second HTTP
timeout per attempt. HTTP 4xx responses are terminal. An undelivered completion
continues to occupy one of the four fixed Agent slots, so an API outage cannot
create an unbounded work queue. Completion payloads are never written to disk or
included in logs, and the backoff uses the stop-aware main loop rather than a
blocking sleep.

The WWW API remains responsible for controls the agent cannot enforce: visitor IP
rate limiting (5 requests/minute), per-target limits, global/node admission,
`no-store` browser responses, audit policy, and deletion of target/result data
after 24 hours.

The systemd unit runs as `ppflight-lg`, grants only `CAP_NET_RAW`, makes the OS
read-only to the process except for its state directory, and restricts available
address families.

## Development and tests

No third-party Python packages are used.

```bash
python3 -m unittest discover -s tests -v
shellcheck install.sh bind.sh uninstall.sh
```

GitHub Actions runs the unit tests against Python 3.9, 3.11 and 3.13 and checks
all shell scripts with ShellCheck.

## Uninstall

Keep local configuration and token state:

```bash
sudo /opt/ppflight-looking-glass/uninstall.sh
```

Permanently remove the installation, configuration, token and service user:

```bash
sudo /opt/ppflight-looking-glass/uninstall.sh --purge
```
