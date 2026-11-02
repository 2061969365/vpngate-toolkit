# vpngate-toolkit

VPNGate 节点采集、转换与真实连通性测试工具。**Go 与 Python 双实现，输出逐字节一致。**

- 无需 tun / root / netns —— 借助 sing-box 1.14+ 的用户态网络栈
- 零第三方依赖（Go 只用标准库，Python 只用标准库）
- 既可独立 CLI 运行，也可作为库嵌入其他程序
- 单进程多 endpoint 批量探测，进程数 = ceil(N/batch)，不是每节点一个

---

## 为什么需要它

VPNGate 有两个节点来源，公开 API 只给约 97 条，插件接口给 200 条滚动窗口：

| 来源 | 单次 | 轮询 3 次并集 |
|---|---|---|
| 插件接口（需解密） | 200 | **308** |
| 公开 API | ~97 | ~102 |
| **去重并集** | — | **309** |

TLS 握手成功 ≠ 节点可用。实测 164 台里 71 台 TLS 可连，但只有 38 台能真正出网 —— 握手法高估约 1.9 倍。本工具做的是**真实出网验证**（通过 SOCKS5 请求 `api.ipify.org` 比对出口 IP）。

---

## 安装

```bash
# Go
cd go && go build -o vpngate ./cmd/vpngate

# Python（无需安装，直接用）
export PYTHONPATH=python
python -m vpngate version
```

运行时需要一个 `sing-box` 1.14+ 二进制（带 `with_openvpn` 标签）。
也可以显式指定：`--singbox /path/to/sing-box` 或环境变量 `VPNGATE_SING_BOX`。

```bash
VER=1.14.4
curl -sLo sb.tar.gz "https://github.com/SagerNet/sing-box/releases/download/v${VER}/sing-box-${VER}-linux-amd64.tar.gz"
tar xzf sb.tar.gz && mv sing-box-${VER}-linux-amd64/sing-box ./sing-box
```

---

## 用法

### 采集

```bash
vpngate harvest --polls 3 --interval 90 --out nodes.json
```

产出：

```
nodes.json              Node 数组（去重）
nodes.json.certs.json   共用证书（ca/cert/key），供后续命令使用
```

参数：

| 参数 | 默认 | 说明 |
|---|---|---|
| `--source` | `both` | `plugin` / `csv` / `both` |
| `--polls` | `1` | 轮询次数，多次会扩大并集 |
| `--interval` | `60` | 轮询间隔（秒） |
| `--timeout` | `30` | 单次 HTTP 超时 |
| `--state` | — | 跨次累积的状态文件 |

### 生成 sing-box 配置

```bash
vpngate generate --in nodes.json --batch 32 --base-port 20000 --out gen/
```

每个 batch 一个文件，端口全局唯一：第 k 批从 `base_port + k*batch_size` 开始。

### 真实探测

```bash
vpngate probe --in nodes.json --batch 32 --timeout 12 \
              --out results.json --usable usable.txt
```

- 每批一个 sing-box 进程，内含 N 个 endpoint + N 个 inbound
- 每个节点独立重试整个 SOCKS5 会话直到截止时间
- `elapsed_ms` 是首次尝试到最终结论的总耗时

### 导出

```bash
vpngate export --in results.json --format csv   --out results.csv
vpngate export --in nodes.json   --format plain --out nodes.txt
vpngate export --in results.json --format singbox --out good.json
```

---

## 作为库使用

### Go

```go
import "vpngate"

nodes, err := vpngate.Harvest(ctx, vpngate.HarvestOptions{
    Sources: []vpngate.Source{
        &vpngate.PluginSource{},
        &vpngate.CSVSource{},
    },
    Polls: 3, Interval: 90 * time.Second,
})
```

扩展点：

| Interface | 用途 |
|---|---|
| `Source` | 新增节点来源 |
| `Prober` | 替换探测方式（如进程内 sing-box） |
| `Exporter` | 自定义输出格式 |

### Python

```python
from vpngate import HarvestOptions, PluginSource, CSVSource, harvest

nodes = harvest(HarvestOptions(
    sources=[PluginSource(), CSVSource()],
    polls=3,
    interval=90,
))
```

---

## 协议细节（逆向所得）

### 容器

```
[0x000 .. 0x0EF]  240 字节头（"VPNGate Data File" + 时间戳 + SOAP_URL + 填充）
[0x0F0 .. 0x103]  20 字节 salt
[0x104 .. EOF]    RC4(key = SHA1(salt)) 密文
```

无 IV、无 AAD、无 GCM tag。

### 明文：SoftEther Pack

```
u32 item_count
item: u32 name_len(含 NUL) + name(name_len-1 字节) + u32 type + u32 count + values
```

`name_len` 包含 NUL 计数，但流里只写 `name_len-1` 字节。**这是最容易写错的地方**，错了会读到 `type=256`。

### sing-box 配置要点

```json
"system": false,
"username": "vpn",
"password": "vpn",
"tls": { "remote_certificate_tls": "none" },
"data_ciphers": ["AES-128-CBC"],
"auth": "SHA1",
"route_no_pull": true,
"ping_restart_disabled": true
```

每一条都是踩过坑的，删掉任何一条都会导致连不上。

---

## 交叉验证

```bash
python tools/crosscheck.py
```

对 `fixtures/api_raw.bin` 与 `fixtures/VPNGate.dat` 分别用 Go 和 Python 解码，
断言输出**逐字节相同**（含 sha256）。

---

## 测试

```bash
cd go   && go build ./... && go vet ./... && go test ./...
cd python && python -m compileall -q vpngate && PYTHONPATH=. python -m unittest discover
```

---

## 目录

```
go/                  Go 实现（模块名 vpngate）
python/vpngate/      Python 包
fixtures/            测试用 DAT 样本
tools/crosscheck.py  跨语言逐字节比对
.github/workflows/   CI + 双语言 Actions 实测
```

---

## 已知限制

- 探测结果依赖探测点网络。Actions（Azure）实测可用率 68%，本机 24%，同一批节点差异极大。
- VPNGate 节点列表每约 11 分钟更新一次，每次换约 5 台。
- 插件接口是 HTTP 明文传输，仅内容做了 RC4 混淆，无任何鉴权。
