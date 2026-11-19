# licguard 三层架构对接文档（协议 v2）

离线场景下的双进程卡密验证框架。主程序 (`app.exe`) 调用独立的验证进程 (`verifier.exe`)，后者用 Ed25519 验卡密签名、用**本机 X25519 密钥**做机器绑定、三副本状态防回滚，最终**只下发解密核心资源所需的密钥**，不下发 true/false。

> **v2 与 v1 不兼容**：卡密格式、REQ1/响应协议、状态格式全部升级。
> 旧卡密会被判"签名无效"；旧状态（`ST1` 前缀）会被自动丢弃，不会把用户锁死。
> 升级后需要重新签发卡密。

## 架构分层（核心设计理念）

代码按"依赖方向"分成三层，上层可以调用下层，下层绝不依赖上层：

```
┌──────────────────────────────────────────────┐
│  高层：应用逻辑（verifier.py / app.py /       │
│        reset.py / keygen.py）                 │
│  只管业务流程："验卡密 → 更新状态 → 下发密钥" │
├──────────────────────────────────────────────┤
│  中层：领域组件（state_store.py / lic_token.py /│
│        machine_key.py）                       │
│  只管一类事情：三副本状态 / 令牌 / 本机密钥    │
├──────────────────────────────────────────────┤
│  底层：工具函数（crypto.py / winops.py / ipc.py）│
│  纯技术原语：加解密 / DPAPI / 注册表ADS / 管道 │
└──────────────────────────────────────────────┘
```

**依赖方向规则：**

```
高层 → 中层 → 底层
         ↓        ↓
      (中层可以直接 import 底层)
```

### 各层文件一览

| 层 | 文件 | 职责 | 依赖 |
|----|------|------|------|
| **底层** | `crypto.py` | 纯密码学原语（b64、HKDF、HMAC、AES-GCM、Ed25519、X25519、sha256） | 标准库 + cryptography |
| **底层** | `winops.py` | Windows 脏活（机器码、注册表、NTFS ADS、DPAPI、原子写、跨进程锁） | ctypes、winreg、crypto |
| **底层** | `ipc.py` | 子进程管道通信（Popen + CREATE_NO_WINDOW） | subprocess |
| **中层** | `machine_key.py` | 本机密钥对（Ed25519 / X25519）+ DPAPI 封装 + 状态密钥派生 | crypto、winops |
| **中层** | `state_store.py` | 三副本状态（文件+注册表+ADS）+ HMAC 完整性 + 取 max 合并 + 跨进程锁 | crypto、machine_key、winops |
| **中层** | `lic_token.py` | 三种令牌（LIC1/ULK1/REQ1）解析+验签 + 机器公钥封装 ck | crypto |
| **高层** | `verifier.py` | 独立验证进程：读状态 → 验卡密 → 更新状态 → 签响应 | crypto、ipc、machine_key、state_store、lic_token、winops |
| **高层** | `activation.py` | 激活流程：生成请求码、导入卡密、定位卡密文件 | crypto、lic_token、machine_key、runtime、winops |
| **高层** | `app.py` | 客户端主程序 + `authorize()` 接口 + 激活菜单 | activation、crypto、ipc、lic_token、winops |
| **高层** | `protected_program.py` | 被保护的示例程序（数字猜谜），授权通过后才被调用 | 标准库 |
| **高层** | `reset.py` | 解除程序：生成请求码 / 消费重置令牌 | crypto、state_store、lic_token、winops |
| **高层** | `keygen.py` | 厂商工具：init / mid / issue / sign-verifier / unlock-token / info | crypto、lic_token、winops |
| **高层** | `sign.py` | 交互式签发工具，内部调用 `keygen.py issue` | lic_token |
| **高层** | `build.py` | 一条命令 Nuitka 编译 + 自动签名 | subprocess |

### 用户（你）需要了解的 API

如果你要把 licguard 集成到自己的产品里，**只需要用两个东西**：

```python
# 方式一：命令行形式（最简单）
# 跑 dist\app.exe 或把 authorize() 的逻辑拷过去

# 方式二：代码形式
from licguard.app import authorize
ok, result = authorize("license.lic")
if ok:
    # result 是解开的核心资源明文
    my_product.run_with(result)
else:
    # result 是错误码或中文原因
    print(f"授权失败: {result}")
```

---

## 威胁模型

下表是 v2 的实际防护能力。它提高的是攻击成本，不是数学意义上的不可破。

| # | 攻击手段 | 防御 |
|---|---------|------|
| 1 | 主程序里把 `if ok:` 改成 `if True` | verifier 只下发 ck；没有 ck 解不开 payload。伪造"成功响应"还需要本机私钥签名 |
| 2 | 卡密拷贝到另一台机器/另一个 Windows 用户 | ck 用**该机器**的 X25519 公钥封装；机器私钥由 DPAPI 保护，换机器/换用户解不开 |
| 3 | 卡密 payload 被改、签了自己的 Ed25519 | 客户端只有厂商公钥，签名伪造不了 |
| 4 | 系统时间回拨 | 三副本 `last` 取最大值；锁定到期时间基于 `max(last, now)`，把时钟调回来也不会提前解锁 |
| 5 | 删除状态文件/注册表/ADS | 三副本必须同时还原；单点删不影响其他副本。**三处全删仍会回到初始状态**（离线固有，见"已知限制"） |
| 6 | 多次试错爆破卡密 | `attempts` 计数 + 指数退避锁定（60s → 120s → 240s → 封顶 3600s）；状态 HMAC 密钥由本机密钥派生，源码公开也伪造不了状态 |
| 7 | verifier.exe 被替换成永远返回 ok 的桩 | app 启动前验 verifier 的厂商签名，verifier 自己启动时也自验；响应还必须由本机私钥签名，桩拿不到私钥 |
| 8 | hook verifier 返回值伪造响应 | 响应由本机 Ed25519 私钥签名，私钥不在响应里；app 用卡密 payload 中（厂商签过的）`msig` 验签 |

**明确不防的**：

- 机器码逆向：Nuitka 编译成机器码，产物里没有 `.py` 源码，但专业逆向人员仍可用 IDA / x64dbg 分析。
- 暴力穷举 ck（32 字节 AES 密钥，不可能）。
- 用调试器 hook `app.authorize()` / `winops.machine_id()` 等函数返回假值。要防这个，核心逻辑得用 C/Rust + 反调试 + 虚拟机混淆。
- **在已授权的机器上**：用户仍可读出 `content_key` 并解密 `payload.bin`。所有客户共用同一份 payload 和 content_key，所以一份解密结果可以传播；这是离线方案的固有上限。
- 同一 Windows 用户下的恶意程序：可以调用 DPAPI 解封本机私钥，或直接读状态文件。DPAPI 挡的是"把文件拷到别的机器/别的用户"。

---

## 文件清单

### 厂商侧（打包进 exe 的东西都不能有厂商私钥）

| 文件 | 作用 | 打包进 exe？ | 谁持有 |
|------|------|------------|--------|
| `keygen.py` | 厂商工具：init / mid / issue / sign-verifier / unlock-token / info | ❌ | 你 |
| `temp/vendor.key` | Ed25519 私钥，32 字节 seed | ❌ | 你（命门，务必离线备份） |
| `vendor_pub.py` | 由 init 自动生成，含 `VENDOR_PUBKEY_B64`，需要提交 | ✅ | 客户 |
| `temp/content.key` | 32 字节固定内容密钥，init 时生成一次不再变 | ❌ | 你 |
| `temp/payload.bin` | AES-GCM 加密后的核心资源（init 时生成） | ✅ | 客户 |
| `build.py` | 一条命令 Nuitka 编译 + 签名流程 | ❌ | 你 |

**所有私密文件都在 `temp/` 里**：`temp/` 已被 `.gitignore` 忽略；`*.lic` 和 `installer/_test/` 也被忽略，避免卡密误提交。

### 客户端运行时（dist/ 目录就是要发给客户的）

| 文件 | 作用 |
|------|------|
| `app.exe` | 主程序 |
| `verifier.exe` | 独立验证进程，有自校验 |
| `verifier.exe.sig` | verifier.exe 的 Ed25519 detached 签名，和 exe 一起发 |
| `payload.bin` | 加密后的核心资源 |
| `temp/` | 客户端运行数据：客户导入的卡密、生成的请求码（首次运行自动创建） |
| `python3*.dll` / `*.pyd` / `cryptography/` | Nuitka 的运行时依赖，必须和 exe 在同一目录 |

**必须整个 `dist/` 目录一起发**，只拷两个 exe 会启动失败。

### 运行时状态（客户机器上）

| 位置 | 路径 | 备注 |
|------|------|------|
| 本机密钥 | `%LOCALAPPDATA%\OfflineLicGuard\machine.key` | DPAPI 封装的 32 字节种子；换机器/用户解不开 |
| 文件 | `%LOCALAPPDATA%\OfflineLicGuard\state.bin` | 三副本之一，`ST2` 格式 |
| 注册表 | `HKCU\Software\OfflineLicGuard\s` | 三副本之二 |
| NTFS ADS | `<verifier.exe>:licstate` | 三副本之三；杀软敏感、复制/解压会丢 |
| 锁文件 | `%LOCALAPPDATA%\OfflineLicGuard\state.lock` | 跨进程互斥，防止并发绕过次数限制 |

---

## 运行流程（时序）

```
客户启动 app.exe
     │
     ├─ ① app._check_verifier_authentic(verifier.exe)
     │     读 verifier.exe 算 SHA-256 → 读 verifier.exe.sig → Ed25519 公钥验签
     │     失败 → 返回 E_VERIFIER_INVALID，退出
     │
     ├─ ② 读卡密 → 验厂商签名 → 取出 payload.msig（本机签名公钥）
     │
     ├─ ③ 生成 32 字节 nonce
     │
     ├─ ④ ipc.run_request(verifier.exe, {"v":2,"nonce":..., "lic":...})
     │
     ▼
  verifier.exe 启动
     │
     ├─ self_check() → 验自己的 SHA-256 签名
     │
     ├─ 取状态锁（state.lock）
     ├─ StateStore.load() → 读三份副本 + HMAC 校验（ST1 旧状态自动丢弃）
     │     有副本验不过 → E_TAMPER
     │     lock_until > now → E_LOCKED
     │     now + tolerance < last → E_CLOCK + 锁
     │
     ├─ lic_token.verify_license()
     │     ① Ed25519 验厂商签名 ② 版本/过期 ③ mid + msig 与本机一致
     │     ④ 用本机 X25519 私钥解 ck（换机器即失败）
     │
     ├─ 次数限制检查
     ├─ StateStore.save()（原子写文件 + 注册表 + ADS）
     │
     └─ 用本机 Ed25519 私钥签响应：
          sig = Sign(seed, canonical({v, ok, ck, runs, lim, ts, nonce}))
     │
     ▼
  app.exe 读响应
     │
     ├─ 失败响应 → 按 code 映射为用户友好提示
     ├─ 用卡密里的 msig 验响应签名 → 失败返回 E_TAG
     └─ crypto.aes_gcm_decrypt(ck, payload.bin) → 核心资源明文
```

---

## 协议（v=2）

### 请求

```json
{
  "v": 2,
  "nonce": "abcdef...（32 字节随机数的 hex 字符串）",
  "lic": "C:\\path\\to\\license.lic"
}
```

### 成功响应

```json
{
  "v": 2,
  "ok": true,
  "ck": "<内容密钥 base64>",
  "runs": 3,
  "lim": 0,
  "ts": 1732740000,
  "nonce": "abcdef...",
  "sig": "<Ed25519_本机私钥(canonical({v,ok,ck,runs,lim,ts,nonce})) 的 base64>"
}
```

`sig` 的私钥由 DPAPI 保护，响应体里没有。app 用卡密 payload 里的 `msig` 验签。

### 失败响应

```json
{"v": 2, "ok": false, "code": "E_EXPIRED", "ts": 1732740000}
```

失败响应不签名（只会导致拒绝，不授予权限）。

错误码映射：

| code | 含义 | 触发位置 |
|------|------|---------|
| E_SELF | verifier 自校验失败 | verifier.self_check() |
| E_REQ | 请求格式错 / 协议版本不匹配 / nonce 非法 | verifier.main() / handle() |
| E_TAMPER | 状态有副本被改坏 | StateStore.load() |
| E_LOCKED | 仍在锁定窗口内 | verifier.handle() |
| E_CLOCK | 系统时间被回拨 | verifier.verify_and_update() |
| E_LIC_READ | 卡密文件不存在或读不到 | verifier.handle() |
| E_RUNS | 次数耗尽 | verifier.verify_and_update() |
| E_MACHINE_KEY | 本机密钥不可用（DPAPI 失败） | verifier.handle() |
| E_BUSY | 状态锁等待超时 | verifier.handle() |
| E_INTERNAL | 未预期异常 | verifier.handle() |
| E_TAG | 主程序收到的响应签名对不上 | app._ask_verifier() |
| E_VERIFIER_INVALID | verifier.exe 的 Ed25519 签名无效 | app._check_verifier_authentic() |
| E_DECRYPT | payload.bin 解密失败 | app._load_core() |

卡密本身的签名/机器码/过期错误是**中文消息**直接返回的（"签名无效"、"机器码不匹配"、"本机密钥不匹配"、"已过期"）。

---

## 卡密格式

顶层是 `LIC1.<payload_b64>.<Ed25519_signature_b64>`，三段。

payload JSON：

```json
{
  "v": 2,
  "lid": "0ba1b22692f48c69",
  "mid": "4dc5a1cb3e55e251...（64 位 hex 机器码）",
  "msig": "<本机 Ed25519 公钥 base64>",
  "menc": "<本机 X25519 公钥 base64>",
  "iat": 1732740000,
  "exp": 1797479947,
  "runs": 0,
  "feat": ["pro"],
  "epk": "<厂商临时 X25519 公钥 base64>",
  "ck": "<nonce(12) || AES-GCM 密文 base64>"
}
```

`ck` 的生成：

```
shared = X25519(厂商临时私钥, menc)
key    = HKDF(shared, "lic-wrap-v2", "content-key")
ck     = nonce(12) || AES-GCM(key, content_key, aad="ck-wrap-v2")
```

`content_key` 就是 `content.key` 文件里的 32 字节，init 时生成一次就固定。**换机器** → 本机 X25519 私钥不同 → shared 不同 → AES-GCM 认证失败 → ck 解不开。卡密里没有任何能推导出机器私钥的公开数据（v1 的 `mid` 派生方案已废弃）。

签名 = `Ed25519_private_sign(crypto.canonical(payload))`。客户端只有公钥，没法伪造签名。

### REQ1 请求码

```json
{
  "v": 2,
  "mid": "<机器码>",
  "msig": "<本机 Ed25519 公钥>",
  "menc": "<本机 X25519 公钥>",
  "mode": "activate",
  "ts": 1732740000,
  "nonce": "<16 字节 hex>"
}
```

`msig` / `menc` 来自本机 DPAPI 保护的种子，公钥可以公开。

---

## 状态字典字段

三副本里存的就是这个 dict，HMAC 做完整性保护，前缀为 `ST2`（旧 `ST1` 会被忽略）。

| 字段 | 类型 | 含义 |
|------|------|------|
| `lid` | str | 当前验证过的卡密唯一 ID |
| `first` | int | 第一次验证成功的时间戳（秒） |
| `last` | int | 三副本里见过的最大时间戳。`now + 容忍 < last` 即判回拨 |
| `runtime` | int | 累计在线时长（秒） |
| `runs` | int | 累计运行次数。和卡密 `runs` 字段（上限）对比 |
| `attempts` | int | 连续错误次数。达 3 次后进入指数退避 |
| `lock_until` | int | 临时锁定到期时间戳 |

**合并规则**：三副本里每个整数字段取**最大值**。改小任一副本都不影响结果；垃圾副本 HMAC 通不过 → `tampered=True` → E_TAMPER。

**HMAC 密钥**：`HKDF(DPAPI 机器种子, "licguard-state-v2", "state-mac")`，不再写死在源码里。

**并发与原子性**：verifier 在 `state.lock` 独占锁内完成 `load → 校验 → save`；状态文件用"临时文件 + fsync + os.replace"原子替换。

---

## 签发一条龙（厂商操作流程）

```bash
# === 第一次：初始化密钥（只做一次，永久有效） ===
cd licguard
python keygen.py init
# 生成 temp/vendor.key / vendor_pub.py / temp/content.key / temp/payload.bin
# 请立刻离线备份 temp/vendor.key

# === 每次给新客户发货 ===
# 1. 编译客户端（默认不带卡密，客户装上是"未激活"状态）
python build.py

# 2. 打安装包（可选，见 installer/setup.iss）
#    发布前必须改 setup.iss 顶部的 AppVersion（当前 2.0.0）；
#    安装包文件名会自动变成 Setup_LicGuard_v<版本>.exe。
#    AppId 不要改，否则升级会被当成另一个软件。

# 3. 客户装好后第一次运行 → 看到激活菜单
#    客户选 1 → 生成 REQ1（含 mid + msig + menc）→ 发给厂商

# 4. 收到请求码后签发卡密
python keygen.py issue --request "REQ1.xxx" --days 365 --runs 0
#    默认写到 temp/license.lic

#    不想记参数就用交互式工具：
python sign.py

# 5. 把卡密内容（或文件）发给客户
#    客户在菜单里选 2 粘贴导入 → 进入使用
```

**手动凭机器码签发**需要客户额外提供两把公钥（否则无法做机器绑定）：

```bash
python keygen.py issue --mid <64位hex> --msig <b64> --menc <b64> --days 365
```

### 客户首次激活流程（客户视角）

```
双击 app.exe
   ↓
没有卡密 → 显示激活菜单
   1) 生成激活请求码（发给厂商）
   2) 导入厂商发回的卡密
   0) 退出
   ↓ 选 1
生成 REQ1，同时保存到 temp/request.txt，并把整行显示出来
   ↓ 客户复制发给你
   ↓ 你跑 keygen.py issue --request ...，把卡密发回
   ↓ 客户选 2，粘贴卡密
验证通过 → 写入 temp/license.lic → 进入程序
```

**注意**：

- 重建密钥（`keygen.py init --reset`）会让**所有已签发的卡密失效**，需要重新编译并重新签发。
- `build.py` 每次重新编译 verifier.exe 后会自动用 vendor.key 给它签名。**签完名的 exe 不能再改**。

---

## 解除锁定流程（reset.py + keygen.py unlock-token）

`reset.py` 打包发给客户，**没有厂商私钥**，必须吃一张 `keygen.py unlock-token` 签好的 `ULK1` 令牌才能生效。

### 安全设计

- 令牌只能用在**绑定的那台机器**（mid 不匹配直接拒绝）；
- `REQ1` 里带当前状态摘要，令牌会绑定它；**用过一次后状态变化，重放会被拒**；
- 默认有效期 3600 秒（`--ttl 0` 才是永不过期）；
- Ed25519 签名客户端伪造不了。

### 重置三种模式

| 模式 | 清理内容 | 适用场景 |
|------|---------|---------|
| `unlock` | 只清 `lock_until` | 系统时间被调导致的临时锁定 |
| `attempts` | 清 `attempts` + `lock_until` | 多次输错卡密被锁定 |
| `full` | 三副本全部清空 | 状态被篡改（E_TAMPER）或换了机器 |

### 客户侧（本机）

```bash
python reset.py request --mode attempts
# REQ1.eyJtaWQiOiI0ZGM1YTFj...
```

### 厂商侧（你这边）

```bash
python keygen.py unlock-token --request REQ1.eyJtaWQiOiI...
# 直接给 mid 也可以，但不会绑定状态摘要（可重放，仅建议应急）
python keygen.py unlock-token --mid 4dc5a1cb... --mode attempts
```

### 客户侧（再发回）

```bash
python reset.py apply --token ULK1.eyJleHAiOjAs...
```

如果检测到 `tampered=True`，`reset.py` 会忽略指定 mode，直接清空三副本。

---

## 底层函数速查

### crypto.py

| 函数 | 做什么 |
|------|--------|
| `b64e` / `b64d` | URL-safe base64 编解码 |
| `canonical(obj)` | 稳定 JSON 字节串（key 排序、无空格） |
| `hkdf(key, salt, info, length=32)` | HKDF-SHA256 |
| `hmac_sha256` / `hmac_equals` | HMAC + 常量时间比较 |
| `aes_gcm_encrypt` / `aes_gcm_decrypt` | AES-GCM |
| `ed25519_sign` / `ed25519_verify` | Ed25519 签名验签 |
| `ed25519_public_from_private` | 由 seed 推导 Ed25519 公钥 |
| `x25519_keygen` / `x25519_exchange` / `x25519_public_from_private` | X25519 ECDH |
| `sha256` / `sha256_hex` | SHA-256 |

### winops.py

| 函数 | 做什么 |
|------|--------|
| `machine_id()` | 64 位 hex 机器指纹（卷序列号 + MachineGuid 的 sha256） |
| `dpapi_protect` / `dpapi_unprotect` | 用当前 Windows 用户 + 本机绑定加解密 |
| `file_write_atomic(path, data)` | 临时文件 + fsync + os.replace |
| `file_lock(path, timeout)` | 跨进程独占锁（msvcrt.locking） |
| `reg_write/read/delete` | HKCU\Software 下的注册表操作 |
| `ads_write/read/delete` | NTFS ADS 读写删（delete 有覆盖兜底） |
| `file_write/read/delete` | 普通文件操作 |

### machine_key.py

| 函数 | 做什么 |
|------|--------|
| `seed()` | 读取/首次生成 32 字节种子（DPAPI 封装） |
| `sign_public_b64()` / `enc_public_b64()` | 本机两把公钥（给 REQ1 / 响应验签用） |
| `sign(data)` | 用本机 Ed25519 私钥给响应签名 |
| `enc_private()` | 本机 X25519 私钥（解卡密里的 ck） |
| `state_mac_key()` | 三副本 HMAC 密钥 |

### ipc.py

| 函数 | 做什么 |
|------|--------|
| `run_request(exe, dict, timeout=15)` | stdin 发 JSON，stdout 收最后一行 JSON，自动 CREATE_NO_WINDOW；输出上限 1 MB |
| `run_line(exe, text, timeout=15)` | 简单版：stdin 给文本，返回 stdout 全文 |

---

## 已知限制与残余风险

### 1. 离线内容最终可被提取

任何没联网的卡密系统，只要攻击者**拿到一份有效卡密并逆向**，最终都能解出内容。v2 把门槛从"改一个跳转"提高到"必须在已授权机器上、以授权用户身份运行并读 DPAPI"，但无法阻止这一点。

### 2. 所有客户共用同一份 payload / content_key

一份解密结果可以传播。若要限制影响面，需要给每个客户生成独立的 payload/content_key（发货时 license + payload 一起发），或把核心资源放到服务端。

### 3. 状态三副本仍可被全部删除

删掉文件、注册表、ADS 三处，状态回到初始值，次数限制重置。这是离线状态存储的固有上限；三副本的作用是**提高发现和删除成本**，不是"防住"。

### 4. 同一用户下的恶意程序

DPAPI 保护的是"文件被拷到别的机器/用户"。如果攻击者已经能以授权用户身份运行代码，他可以解封机器私钥、读状态文件、hook 进程。要防这个需要 C/Rust + 反调试 + 代码签名 + 服务端校验。

### 5. 杀软误报

ADS、注册表、读卷序列号都可能触发启发式。建议用 EV 代码签名证书、不要加壳、必要时提交误报申诉。

### 6. 状态写入的极端情况

文件是原子写，但注册表和 ADS 不是。若断电发生在三副本写入之间，可能出现"一份新、两份旧"，取 max 合并通常能自愈；若某份被写坏，会判 E_TAMPER，需要重置令牌。

### 7. 机器密钥丢失

删除 `machine.key` 或换 Windows 用户等价于换机器：卡密需要重新签发，旧状态会被丢弃。请提前告知客户不要清理 `%LOCALAPPDATA%\OfflineLicGuard`。

---

## v1 → v2 变更摘要

| 项目 | v1 | v2 |
|------|----|----|
| 机器绑定 | `HKDF(mid)`，mid 明文可推导 | X25519 ECDH + DPAPI 机器私钥 |
| 响应认证 | `HMAC(ck, ...)`，ck 在响应里（自证循环） | 本机 Ed25519 签名，公钥来自卡密 |
| 状态 HMAC 密钥 | 写死在源码（三段 XOR） | DPAPI 机器种子派生 |
| 状态并发 | 无锁读改写 | `state.lock` 跨进程锁 |
| 状态写入 | 直接覆盖 | 临时文件 + fsync + os.replace |
| 状态格式 | `ST1` | `ST2`（ST1 自动丢弃） |
| 重置令牌 | 可重放、默认可永不过期 | 绑定状态摘要、默认 3600s |
| 解析健壮性 | b64/hex 异常可崩溃 | 统一 TokenError + 长度/格式校验 |
