# vpngate-toolkit —— 共享实现规范

Go 与 Python 两套实现必须严格遵守本文件。`SPEC.md` 是唯一事实来源，任何偏离都算 bug。

---

## 0. 背景（实现者必读）

VPNGate 有两个节点来源：

**A. 插件接口（主力）**

```
GET http://x{a}.x{a}.client.api.vpngate2.jp/api/     a ∈ 0-9a-fxyz
→ 200 application/octet-stream，约 74.8 KB，以 "[VPNGate Data File]" 开头
```

容器格式：

```
[0x000 .. 0x0EF]  240 字节头（"VPNGate Data File" + 时间戳 + SOAP_URL + 填充）
[0x0F0 .. 0x103]  20 字节 salt
[0x104 .. EOF]    RC4(key = SHA1(salt)) 密文，无 IV / 无 AAD / 无 tag
```

解密后是 SoftEther Pack：

```
u32 item_count
item: u32 name_len(含 NUL) + name + u32 type + u32 count + values
  type 0: count × u32 (大端)
  type 1: count × (u32 len + bytes)   二进制
  type 2: count × (u32 len + bytes)   字符串
  type 3: count × (u32 len + bytes)   字符串
  type 4: count × u64
```

外层 6 个元素：`data`（内层 Pack，可能 zlib 压缩）/ `data_size` / `sign` / `timestamp` / `compressed` / `WebLink`

内层 40 列 × `NumHosts` 行，列式存储。本工具只用这些列：

| 列名 | 类型 | 说明 |
|---|---|---|
| `IP` | str | 节点 IP |
| `CountryShort` | str | 两位国家码 |
| `Fqdn` | str | 域名 |
| `HostName` | str | 主机名 |
| `SslPorts` | str | SSL-VPN 端口，逗号分隔，可能为空 |
| `L2TP` | u32 | 0/1 |
| `UdpPort` | u32 | 0 表示无 |
| `Score` | u32 | 评分 |
| `NumClients` | u32 | 当前连接数 |

**B. 公开 API**

```
GET https://www.vpngate.net/api/iphone/
→ text/csv，首行可能以 "*" 开头，第二行 "#HostName,IP,Score,..."
```

关键列：`IP`、`CountryShort`、`HostName`、`Score`、`NumVpnSessions`、`OpenVPN_ConfigData_Base64`

从 `OpenVPN_ConfigData_Base64` 解出 `.ovpn` 文本，用正则取端口：

```
^remote\s+\S+\s+(\d+)
```

**证书**：所有节点共用同一套 `ca` / `cert` / `key`（从任意一条 CSV 记录内嵌的 `.ovpn` 里提取）。
账号固定 `vpn` / `vpn`。

---

## 1. 目录结构

```
vpngate-toolkit/
├── SPEC.md
├── go/
│   ├── go.mod                    module vpngate
│   ├── cmd/vpngate/main.go       CLI 入口
│   ├── vpngate.go                公开 API（package vpngate）
│   ├── dat.go                    容器解码
│   ├── pack.go                   Pack 解析
│   ├── source_plugin.go
│   ├── source_csv.go
│   ├── merge.go
│   ├── singbox.go                配置生成
│   ├── probe.go                  批量探测
│   ├── export.go                 json / csv / plain / singbox
│   └── *_test.go
└── python/
    ├── pyproject.toml
    └── vpngate/
        ├── __init__.py
        ├── dat.py
        ├── source.py
        ├── merge.py
        ├── singbox.py
        ├── probe.py
        ├── export.py
        └── cli.py
```

要求：

- **Go**：零第三方依赖（只用标准库）。
- **Python**：零第三方依赖（只用标准库），支持 `python -m vpngate`。

---

## 2. 数据模型

两语言序列化出的 JSON 必须**逐字段一致**。

```json
{
  "ip": "219.100.37.24",
  "country": "JP",
  "fqdn": "public-vpn-39.opengw.net",
  "hostname": "public-vpn-01-03.vpngate.v4.open.ad.jp",
  "ssl_ports": [443],
  "l2tp": false,
  "udp_port": 0,
  "score": 1234,
  "sessions": 3,
  "source": "both",
  "first_seen": 1762000000,
  "last_seen": 1762000900
}
```

约束：

- `ip` 必须是合法 IPv4 点分十进制，否则丢弃
- `ssl_ports` 升序去重
- `source ∈ {"plugin","csv","both"}`
- `first_seen` / `last_seen` 为 Unix 秒
- JSON 输出按 `ip` 字符串升序
- 缺失字符串字段用 `""`，缺失数值用 `0`，`ssl_ports` 为空不是 `null`

---

## 3. 核心 API（两语言同名同义）

### 3.1 解码

```
DecodeDAT(blob []byte) (RecordSet, Meta, error)
decode_dat(blob: bytes) -> tuple[RecordSet, Meta]
```

`Meta` 含 `salt_hex`、`key_hex`、`num_hosts`、`columns`、`plaintext_len`。

错误条件（必须报错，不能静默）：

- 长度 < 276
- 开头不是 `[VPNGate Data File]`
- Pack 解析后 `off != len(buf)`（尾部多余字节）
- `NumHosts` 缺失或 > 100000
- 任一列长度与 `NumHosts` 不一致

### 3.2 Source

```
type Source interface {
    Name() string
    Fetch(ctx context.Context) ([]Node, error)
}
```

`PluginSource`：

- 依次尝试 `a ∈ "0123456789abcdefxyz"`，首个成功即返回
- 单次 HTTP 超时默认 30s，可配
- 必须带 `User-Agent: Mozilla/5.0`

`CSVSource`：

- 解析失败的行跳过并计数，不整体失败
- 必须提取证书（`ca`/`cert`/`key`），供 `GenerateConfig` 使用

### 3.3 合并

```
Merge(nodes []Node) []Node
merge(nodes: list[Node]) -> list[Node]
```

规则：

- 按 `ip` 去重
- 两侧都有 → `source = "both"`
- `ssl_ports` = 两侧并集，升序去重
- `score` / `sessions` 取较大值
- `fqdn` / `hostname` 取第一个非空
- `first_seen` 取较小值，`last_seen` 取较大值

### 3.4 sing-box 配置生成（性能关键）

**不要一个节点起一个 sing-box 进程。** 用批量模式：一个进程承载 N 个 endpoint + N 个 inbound。

```
生成 N 个 endpoint: tag = "ep0".."ep{N-1}"
生成 N 个 inbound : type=mixed, tag="in0".."in{N-1}", listen=127.0.0.1, listen_port=basePort+i
route.rules: [{inbound: "in{i}", outbound: "ep{i}"}]
```

每个 endpoint：

```json
{
  "type": "openvpn-client",
  "tag": "ep0",
  "server": "<node.ip>",
  "server_port": <node.ssl_ports[0]>,
  "network": "tcp",
  "system": false,
  "username": "vpn",
  "password": "vpn",
  "tls": {
    "certificate": ["<ca 按行>"],
    "client_certificate": ["<cert 按行>"],
    "client_key": ["<key 按行>"],
    "remote_certificate_tls": "none"
  },
  "data_ciphers": ["AES-128-CBC"],
  "auth": "SHA1",
  "route_no_pull": true,
  "ping_restart_disabled": true
}
```

顶层固定：

```json
"log": {"level": "error"},
"inbounds": [...],
"endpoints": [...],
"route": {"rules": [...]}
```

**必须注意**（都是踩过的坑，不要"优化"掉）：

- `system: false` —— 否则要 root + tun
- `username`/`password` = `vpn`/`vpn` —— 否则 `authentication failed`
- `remote_certificate_tls: "none"` —— VPNGate 证书无 serverAuth EKU
- `ping_restart_disabled: true` —— 否则空闲十几秒断
- `network: "tcp"` —— VPNGate 只开 TCP

### 3.5 Probe

```
type Prober interface {
    Probe(ctx context.Context, nodes []Node) ([]Result, error)
}
```

`Result`：

```json
{
  "ip": "1.2.3.4",
  "port": 443,
  "country": "JP",
  "ok": true,
  "egress": "1.2.3.4",
  "elapsed_ms": 1800,
  "error": ""
}
```

`SingBoxBatchProber` 行为：

1. 每批 `BatchSize` 个节点（默认 32），生成一个配置、启动一个 sing-box 进程
2. 等待启动：轮询各 inbound 端口可连接
3. 对每个端口并发发起一次 SOCKS5 请求 `https://api.ipify.org`，超时 `ProbeTimeout`（默认 12s）
4. 校验返回是合法 IPv4
5. 关闭进程，进入下一批
6. 任何单节点失败不影响其他节点
7. 进程启动失败或提前退出 → 该批全部标记失败，`error` 写明原因

**并发**：批内并发探测；批之间串行（避免进程爆炸）。

**降级预筛（可选）**：提供 `TCPPreFilter`，先用纯 TCP 连接筛掉不可达端口，
减少进入 sing-box 的节点数。默认关闭，CLI 用 `--prefilter` 开启。

### 3.6 Export

支持的格式：

| 格式 | 说明 |
|---|---|
| `json` | 完整 Node 数组 |
| `csv` | `ip,port,country,egress,elapsed_ms,ok` |
| `plain` | 每行 `ip:port` |
| `singbox` | 单节点 sing-box 配置（选第一个可用节点） |

---

## 4. CLI 契约

两个实现必须提供**完全相同的子命令与参数名**。

```
vpngate harvest   [--source plugin|csv|both] [--polls N] [--interval SEC]
                  [--timeout SEC] [--out FILE] [--state FILE]
vpngate generate  [--in FILE] [--batch N] [--base-port N] [--out DIR]
vpngate probe     [--in FILE] [--batch N] [--timeout SEC] [--workers N]
                  [--prefilter] [--out FILE] [--usable FILE]
vpngate export    [--in FILE] [--format json|csv|plain] [--out FILE]
vpngate version
```

默认值：

- `--source both`
- `--polls 1`
- `--interval 60`
- `--timeout 30`（harvest）/ `12`（probe 的 PROBE_TIMEOUT）
- `--batch 32`
- `--base-port 20000`
- `--workers` = `min(batch, 32)`

退出码：`0` 成功，`1` 运行错误，`2` 参数错误。

`harvest` 的 `--state` 用于跨次累积（读写同一份 Node 数组，合并后写回）。

---

## 5. 输出稳定性（交叉验证用）

同一份输入 `api_raw.bin`，两语言必须满足：

- `salt_hex` 完全相同
- `key_hex` 完全相同
- `num_hosts == 200`
- 唯一 IP 数相同
- 按 `ip` 排序后，`ip` 序列**逐元素相同**

**JSON 序列化要求**：

- 键顺序固定：`ip, country, fqdn, hostname, ssl_ports, l2tp, udp_port, score, sessions, source, first_seen, last_seen`
- 无空格：`{"ip":"1.2.3.4",...}`（Go 用 `json.Marshal` 默认即无空格；Python 用 `separators=(',',':')`）
- 数字不加 `.0`，布尔小写
- 文件末尾**一个换行**

---

## 6. 测试向量

`fixtures/api_raw.bin`（75,033 B）：

```
salt  = 6c251f5c40d5e1739b0ef4395da111872639f2bd
key   = SHA1(salt) = 74ffac3bd2b906484c3cfc012db20ee0ed651a77
NumHosts = 200
唯一 IP  = 198
```

`fixtures/VPNGate.dat`（26,900 B，内层 zlib）：

```
salt = 99c6aac62cf7e3e29f0e43c596217764ef43e51b
key  = 4f8fb1176b765039b4be7c5eddd3bdd0abe83703
NumHosts = 200
```

单元测试最低要求：

- Pack 解析的 5 种 type 各一个用例
- 容器长度/魔数错误用例
- 合并去重用例（重叠、仅左、仅右）
- sing-box 配置生成的 JSON 结构断言
- 端口解析（`remote 1.2.3.4 443`）

---

## 7. 性能与资源要求

| 项 | 目标 |
|---|---|
| 解码 200 节点 | < 20 ms（Go）/ < 80 ms（Python） |
| 常驻内存 | Go < 30 MB；Python < 80 MB |
| 探测 260 节点 | < 6 分钟（batch 32，8 并发） |
| sing-box 进程数 | ≤ ceil(N/32)，**不得**每节点一个进程 |
| 文件句柄 | 探测结束必须全部关闭，无泄漏 |

禁止：

- 把整个 `.ovpn` 或证书重复写进每个 endpoint（证书在配置顶层只出现一次？不——sing-box 每个 endpoint 需要独立 `tls` 块，但**同一批内可共用同一份字符串切片**，不要重复解析 PEM）
- 每节点 fork 一次 sing-box
- 无上限的 goroutine / 线程

---

## 8. 可扩展性要求

必须留出这些扩展点，且不得破坏零依赖：

**Go**

- `Source` / `Prober` / `Exporter` 三个 interface
- 所有 HTTP 客户端可注入（`*http.Client`）
- 所有超时可配
- `vpngate.Node` 公开，可被外部直接使用
- 提供 `DecodeDAT` 等纯函数供库调用

**Python**

- 同样的抽象用 `Protocol` / ABC 表达（或简单基类）
- 所有类可在不继承的情况下用鸭子类型替换
- `python -m vpngate.cli` 与 console_script 双入口

两语言都要能作为库被 import，不产生 CLI 副作用（不能在 import 时解析 argv 或启动进程）。

---

## 9. 验收清单

- [ ] `go build ./...` 通过，`go vet ./...` 无告警，`go test ./...` 全绿
- [ ] `python -m compileall` 通过，`python -m unittest` 全绿
- [ ] 两语言对同一 fixture 的 `num_hosts` / 唯一 IP / 排序后 IP 列表完全一致
- [ ] 生成的 sing-box 配置能被 `sing-box check -c` 通过
- [ ] `probe` 在真实节点上至少跑通 1 台，`egress` 为合法 IPv4
- [ ] 无第三方依赖（`go.mod` 无 require；Python 无 install_requires）
- [ ] GitHub Actions 里两语言各跑一次，输出可比对

---

## 10. 补充约定（v2，两语言必须一致）

### 10.1 `decode` 的确定性输出

`decode` 用于跨语言逐字节比对，**不得引入任何非确定值**：

| 字段 | 固定值 |
|---|---|
| `source` | `"plugin"` |
| `first_seen` | `0` |
| `last_seen` | `0` |

排序：按 `ip` 字符串升序做**稳定排序**；同一 IP 的重复记录保持解码时的原始行序。
**不得去重**：`NumHosts=200` 时输出 200 条记录（唯一 IP 可能是 198）。
不得调用任何时间函数。

**stderr meta 行**（每次 decode 只输出一行，精确到空格）：

```
salt=<hex> key=<hex> hosts=<n> columns=<n> plaintext=<bytes>
```

`columns` 只统计 `count == NumHosts` 的数据列，`NumHosts` 自身不算。

**JSON 序列化**：键顺序 `ip,country,fqdn,hostname,ssl_ports,l2tp,udp_port,score,sessions,source,first_seen,last_seen`，
紧凑格式（无空格、无缩进），非 ASCII 不转义，整个数组一行，文件末尾恰好一个 `\n`。

**`version` 输出**：`vpngate 1.0.0`

### 10.2 证书旁车文件

`harvest` 在写出节点文件的同时，写一个同名旁车：

```
out/nodes.json        ← Node 数组
out/nodes.json.certs.json  ← {"ca":["-----BEGIN..."],"cert":[...],"key":[...]}
```

`generate` 与 `probe` 按以下顺序取证书：

1. 命令行 `--certs FILE`（若提供）
2. `<in>.certs.json`
3. 与 `<in>` 同目录的 `certs.json`
4. 联网从公开 CSV 提取（最后兜底）

取不到时必须报错退出，不能静默使用空证书。

### 10.3 `export --format csv` 的输入自适应

输入可能是 Node 数组，也可能是 probe 的 Result 数组，按元素是否含 `ok` 字段判断：

- Result 数组 → 各列正常输出
- Node 数组 → `egress=""`、`elapsed_ms=0`、`ok=false`

`--format singbox` 在 CLI 中也必须支持（SPEC 3.6 已定义），输出单个节点的完整 sing-box 配置。
选择规则：若输入是 Result 数组，取第一个 `ok=true` 且 `elapsed_ms` 最小的；若是 Node 数组，取第一个 `ssl_ports` 非空且 `score` 最大的。

