# PPFlight Looking Glass Agent（网络探测代理）

PPFlight Looking Glass Agent 用于在 PPFlight 的各个区域执行网络探测任务。它不接受任何入站连接：首次使用 ADMIN 生成的一次性绑定码完成绑定，之后仅通过出站 HTTPS 发送心跳、领取任务并返回经过安全处理的结果。

Agent 应部署在被测网络所在区域内的一台隔离、低权限虚拟机中。如果能够提供小型专用虚拟机，**请勿**将其安装在 Proxmox 管理宿主机上。

## 支持的系统

- Debian 和 Ubuntu（`apt`）
- RHEL、Rocky Linux、AlmaLinux 和 CentOS Stream（`dnf`）
- 能通过 `yum` 提供所需软件包的旧版 CentOS
- systemd 和 Python 3.9 或更高版本

安装程序会自动选择 `apt`、`dnf` 或 `yum`，并安装 Python、`ping`、`traceroute`、`mtr` 和 CA 证书。在 RHEL 系列系统中，如果默认 Python 版本过低，安装程序会尝试安装 Python 3.9。

## 从 GitHub 安装

该仓库目前是私有仓库，目标服务器需要先获得 GitHub 访问权限，然后执行：

```bash
git clone https://github.com/ppflight/ppflight-looking-glass-agent.git
cd ppflight-looking-glass-agent
sudo ./install.sh
```

`install.sh` 会在安装结束时安全地提示输入一次性绑定码。输入内容不会显示，并通过标准输入传递给 Agent，因此不会保存在 Shell 历史记录中，也不会暴露为命令行参数。

如需无人值守安装，请将一次性绑定码单独保存到仅 root 可读的文件中：

```bash
chmod 600 /root/ppflight-lg-binding-code
sudo ./install.sh --bind-code-file /root/ppflight-lg-binding-code
rm -f /root/ppflight-lg-binding-code
```

如需只安装、暂不绑定和启动服务：

```bash
sudo ./install.sh --non-interactive
sudo nano /etc/ppflight-looking-glass/config.json
sudo /opt/ppflight-looking-glass/bind.sh
```

仓库本身不包含令牌、密钥或绑定码。绑定成功后，Agent 令牌会保存到 `/var/lib/ppflight-looking-glass/state.json`，文件权限为 `0600`，所有者为非 root 账户 `ppflight-lg`。

## 配置

安装程序会将 `config.example.json` 复制到：

```text
/etc/ppflight-looking-glass/config.json
```

配置文件已预设生产 API 地址。`agent_name` 和 `location` 默认值有意设置为 `unconfigured`，它们只是在本地显示的说明性占位符。一次性绑定码决定真实的 ADMIN 节点身份、节点代码、区域和公开状态；Agent 无权选择或覆盖这些属性。轮询间隔和请求超时只能使用 Agent 允许的受限范围。

无需发起 API 请求即可检查本地安装：

```bash
sudo -u ppflight-lg /opt/ppflight-looking-glass/python3 \
  /opt/ppflight-looking-glass/agent.py \
  --config /etc/ppflight-looking-glass/config.json check
```

查看服务诊断信息：

```bash
ag-lg
```

安装程序会创建 `/usr/local/bin/ag-lg`。运行 `ag-lg` 后会打开中文交互式 Agent 控制台，显示服务状态、版本与平台、绑定状态、节点 ID、API 地址、连接检查结果、探测程序和不可修改的安全上限。控制台会主动将标准输出和错误输出切换为 UTF-8，因此在默认终端编码为 `latin-1` 的系统上也能正常显示中文。控制台绝不会显示 Bearer Token、访客 IP 指纹、探测目标、探测输出或原始日志内容。升级安装时，安装程序只会删除带有 PPFlight 所有权标记的旧 `/usr/local/bin/ag`；其他软件的同名命令不会被修改。

也可以使用以下非交互命令：

```bash
ag-lg status     # 查看本地服务、绑定状态和安全限制
ag-lg summary    # 查看安全的 ADMIN 节点信息和匿名化的 24 小时统计
ag-lg check      # 查看本地状态和 API 连接摘要
ag-lg logs       # 查看分类后的日志数量，不显示原始日志内容
ag-lg bind       # 使用 ADMIN 一次性绑定码安全绑定或重新绑定
ag-lg version    # 查看版本信息
```

`ag-lg summary` 调用 `POST /agent/control/summary`。控制台只会渲染 `data.node` 和 `data.stats` 固定白名单中的字段，包括 24 小时聚合总数、已知状态计数、匿名访客指纹数量和安全拒绝数量。如果旧版 WWW 尚未提供该接口，控制台会明确提示，同时保持所有本地状态命令可用。

控制台也可能显示 `active_ip_block_count`，但它只是一个汇总数字。被封禁的具体 IP 地址仅限 PPFlight 超级管理员查看，绝不会发送到 Agent 节点，也不会由 Agent 节点保存或显示。

## API 协议

所有请求和响应均使用 JSON，并设置 `Cache-Control: no-store`。Agent 只会使用 `api_base_url` 下的以下固定接口：

| 用途 | 请求方法与路径 | 身份验证方式 |
| --- | --- | --- |
| 一次性绑定 | `POST /agents/bind` | JSON 中的 `binding_code` |
| 发送心跳 | `POST /agent/heartbeat` | Agent Bearer Token |
| 领取任务 | `POST /agent/jobs/claim` | Agent Bearer Token |
| 提交任务结果 | `POST /agent/jobs/{uuid}/complete` | Agent Bearer Token |
| 获取安全控制台摘要 | `POST /agent/control/summary` | Agent Bearer Token |

绑定响应包含 `agent_token` 和 `node.id`。领取到的任务包含 `id`、`method`、`target`、`resolved_addresses`、`resolution_fingerprint` 及其执行约束。API 支持的方法为 `ping`、`trace` 和 `mtr`；其中 `trace` 在本地使用 `traceroute` 程序执行。

服务器提供的任何附加参数都会被忽略，所有命令都由本地固定参数数组构造。任务成功后，Agent 会提交 `status: completed`、已验证的 DNS 解析证明，以及经过长度限制的字符串数组 `result.output`。任务失败时会提交 `status: failed`，并附带结构化错误代码和错误消息。

## 安全边界

除 WWW API 的安全控制外，Agent 还会独立强制执行以下限制：

- 探测目标必须且只能是一个域名、IPv4 地址或 IPv6 地址；
- 拒绝 URL、端口、路径、区域标识符和命令参数；
- 拒绝回环、私有、链路本地、组播、保留地址和云元数据地址；
- DNS 返回的每一个地址都必须是公网地址；探测前会在可强制终止的隔离解析进程中连续解析两次，两次结果必须完全一致，命令最终只接收锁定后的 IP 地址；
- 子进程始终使用 `shell=False`、固定环境变量和固定参数数组；
- Ping 固定最多发送 5 个数据包，Trace 固定最多 20 跳，MTR 固定为 5 轮、最多 20 跳（低于 10 轮的安全上限），并使用非 root 用户可执行的 1 秒间隔；
- 领取任务的 HTTP 往返、DNS 验证和探测过程共同使用服务器约定的 15 秒单调时钟预算；执行会提前约 1 秒结束，为首次提交结果预留网络时间。Agent 会验证服务器的 `deadline_at`，但不会将其与节点本地时钟直接比较，以避免时钟偏差造成误判超时；
- 标准输出和标准错误会被增量读取，并设置 64 KiB 的严格内存上限；一旦达到上限就立即终止整个进程组，结果中的非公网跳点会替换为 `private hop`；
- 单个节点最多同时执行 4 个任务；
- 任务结果和访客目标不会进入磁盘队列，也不会持久化到 Agent 磁盘。

结果提交采用有界重试策略：网络错误或 HTTP 5xx 响应会从内存中最多重试 3 次，每次采用短暂退避，单次 HTTP 超时为 2 秒。HTTP 4xx 响应被视为终止性错误，不会重试。尚未成功提交的任务会继续占用 4 个固定 Agent 并发槽位中的一个，因此 API 故障不会产生无限增长的工作队列。结果载荷不会写入磁盘或日志，退避等待由可响应停止信号的主循环管理，不使用阻塞式睡眠。

WWW API 仍负责执行 Agent 无法独立实施的控制：访客 IP 限流（每分钟 5 次）、目标限流、全局及节点准入、浏览器响应的 `no-store`、审计策略，以及在 24 小时后删除目标和结果数据。

systemd 服务以 `ppflight-lg` 用户运行，仅授予 `CAP_NET_RAW` 权限。除自身状态目录外，操作系统文件对该进程只读，并限制其可使用的地址族。

## 开发与测试

Agent 不依赖第三方 Python 软件包。

```bash
python3 -m unittest discover -s tests -v
shellcheck install.sh bind.sh uninstall.sh ag-lg
```

GitHub Actions 会分别使用 Python 3.9、3.11 和 3.13 运行单元测试，并使用 ShellCheck 检查全部 Shell 脚本。

## 卸载

保留本地配置和令牌状态：

```bash
sudo /opt/ppflight-looking-glass/uninstall.sh
```

永久删除程序、配置、令牌和服务用户：

```bash
sudo /opt/ppflight-looking-glass/uninstall.sh --purge
```
