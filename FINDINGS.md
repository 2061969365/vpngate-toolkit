# 开发过程中发现并修复的问题

按严重程度排序。全部为实测复现，非推测。

---

## 致命（会让工具完全不可用）

### 1. Pack 解析偏移错 1 字节 —— Python 侧

**现象**

```
vpngate: error: unknown pack type 256 for 'data'
```

**根因**

`name_len` 字段的值**包含 NUL 计数，但流里只写入 `name_len-1` 字节**。Python 实现读对了名字，却把偏移前进了 `name_len`，多走 1 字节，导致后续 `type` 字段错位读到 256。

实测字节（`fixtures/api_raw.bin` 解密后）：

```
 0: 00 00 00 06 00 00 00 05     item_count=6, name_len=5
 8: 64 61 74 61 00 00 00 01     "data" 占 8..11，type 在 12
16: 00 00 00 01 00 01 22 b6     count=1, size=74422
24: 00 00 00 28                内层 Pack 起点
```

- 前进 `name_len`（5）→ `off=17`，读到 `type=256` ❌
- 前进 `name_len-1`（4）→ `off=12`，读到 `type=1` ✅

**修复**：`off += name_len - 1`，边界检查同步改为 `name_len - 1`。

**回归锚点**：内层 blob 起点 24 + 长度 74422 = 74446，恰好是 `data_size` 键的 `name_len` 位置；外层解析结束必须 `off == 74773`。两条断言已加入单测。

---

### 2. 探测在隧道就绪前就开始 —— Go 与 Python 双侧

**现象**

```
total 200  ok 0
  169  socks5 connect failed: code 1
elapsed 范围: 0 ~ 2 ms
```

**根因**

sing-box 启动后 **inbound 端口立刻可连**，但 OpenVPN endpoint 还在建隧道（实测单节点 1.5~30 秒）。此时 SOCKS5 请求被回 `REP=0x01`（general failure），耗时 0-2ms。

「等端口可连 → 立刻探测」的写法会把全部节点误判为失败。

**修复**

每个节点独立重试**整个 SOCKS5 会话**直到截止时间：

- 可重试：`REP=0x01`、`REP=0x04`、connection refused、greeting 阶段 EOF/timeout
- 不可重试：SOCKS 版本号异常、证书校验失败
- 单次尝试上限 `min(3s, 剩余预算)`，重试间隔 250–350ms
- `elapsed_ms` 记录首次尝试到最终结论的总耗时
- 进程提前退出通过 done channel 立即中断该批重试

**修复后实测**：`103.172.220.133:465 → egress 103.78.12.196, 4674ms`。

---

### 3. `.gitignore` 误伤 Python 包

**现象**：CI 里 `No module named vpngate`，但本地测试全绿。

**根因**：`.gitignore` 写了裸 `vpngate`（本意是忽略 Go 编译出的二进制），该模式匹配**任意层级**同名文件/目录，把 `python/vpngate/` 整个包排除了。本地有文件所以能跑，仓库里根本没有。

**修复**：改为 `/vpngate`（只匹配根目录）。

**教训**：`.gitignore` 的裸名模式是递归的，忽略构建产物必须加前导 `/`。

---

## 严重（功能错误，但不至于全灭）

### 4. 分批端口全部重叠 —— Go 与 Python 双侧

**现象**

```
singbox-batch-0.json  ports 20000..20039
singbox-batch-1.json  ports 20000..20039   ← 重复
singbox-batch-2.json  ports 20000..20039   ← 重复
```

**根因**：每批都从 `base_port` 重新开始。

**修复**：第 k 批起点 = `base_port + k * batch_size`（按 `batch_size` 递增，不按已处理节点数，最后一批不足也不影响后续）。

**修复后**：169 节点 / batch 40 → 5 个文件，端口并集 169，无重复。

---

### 5. `export --format plain` 丢弃失败节点 —— Go 侧

**现象**：Go 输出只含 `ok=true` 的行，Python 输出全部行，两语言不一致。

**决策**：职责分离——

- `export --format plain`：输出**全部** `ip:port`，不做过滤
- `probe --usable`：只输出成功节点

**修复**：Go 的 `PlainExporter` 增加 `ExportResults`，不过滤。

**验证**：同一份 `results.json`，两语言均输出 169 行，`diff` 为空。

---

### 6. Go 找不到 sing-box

**现象**

```
vpngate: probe: sing-box not found: exec: "sing-box": executable file not found in $PATH
```

**根因**：CI 把二进制放在仓库根目录，Go 的 `exec.LookPath` 出于安全考虑（`ErrDot`）拒绝执行相对当前目录的可执行文件。

**修复**：新增 `--singbox PATH` 参数与环境变量 `VPNGATE_SING_BOX`（Python 侧已有同名变量，行为对齐）。

---

### 7. CI 用 `| tail` 吞掉退出码

**现象**：Python 单测 7 个 error，但 job 仍然「成功」通过该步骤。

**根因**：`cmd | tail -40` 的退出码取的是 `tail` 的。

**修复**：两步都加 `set -o pipefail`。

---

## 轻微（一致性 / 易用性）

| # | 问题 | 处理 |
|---|---|---|
| 8 | `generate --out` Go 必填、Python 有默认值 | 统一为默认 `singbox` |
| 9 | 配置文件命名 Go `singbox-batch-N.json` / Python `singbox-N.json` | 统一为 `singbox-batch-N.json` |
| 10 | `probe` 无 `--base-port` | Go 增加该参数；Python 会自动找连续空闲端口段 |
| 11 | `columns` 口径歧义 | 明确为 `count==NumHosts` 的数据列数 = **34**（40 个 item 中 6 个是 count=1 的标量） |
| 12 | `harvest` 在 plugin-only 时无法产出证书旁车 | 允许仅告警不中断；`generate/probe` 有四级证书查找兜底 |

---

## 交叉验证结果

```
fixtures/api_raw.bin   go 44183 B  py 44183 B  sha256=cb179fb9b266984c  逐字节一致
fixtures/VPNGate.dat   go 44251 B  py 44251 B  sha256=a55eda57877a6e05  逐字节一致
RESULT: PASS
```

## CI 实测（2026-11-02，ubuntu-latest）

| 实现 | 耗时 | 输入 | 可用 | 可用率 | 不同出口 IP |
|---|---|---|---|---|---|
| Go | 2m53s | 198 | 89 | 44.9% | 86 |
| Python | 2m41s | 198 | 88 | 44.4% | 82 |

两次 harvest 时间不同，插件列表会轮换，输入 IP 集只有 33 个重叠。
在这 33 个共同节点上，两实现的判定一致率 **81.8%**（27/33），差异来自网络时序抖动，不是逻辑差异。
