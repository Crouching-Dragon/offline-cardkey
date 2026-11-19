# licguard 三层架构对接文档

离线场景下的双进程卡密验证框架。主程序 (`app.exe`) 调用独立的验证进程 (`verifier.exe`)，后者用 Ed25519 验卡密签名、AES-GCM 做机器绑定、三副本状态防回滚，最终**只下发解密核心资源所需的密钥**，不下发 true/false。

## 架构分层（核心设计理念）

代码按"依赖方向"分成三层，上层可以调用下层，下层绝不依赖上层：

```
┌──────────────────────────────────────────────┐
│  高层：应用逻辑（verifier.py / app.py /       │
│        reset.py / keygen.py）                 │
│  只管业务流程："验卡密 → 更新状态 → 下发密钥" │
├──────────────────────────────────────────────┤
│  中层：领域组件（state_store.py / lic_token.py）│
│  只管一类事情：三副本状态 / 令牌解析+验签       │
├──────────────────────────────────────────────┤
│  底层：工具函数（crypto.py / winops.py / ipc.py）│
│  纯技术原语：加解密 / 注册表ADS / 管道通信      │
└──────────────────────────────────────────────┘
```

**为什么这样分？** 你（0 基础用户）只需要看高层。底层那些 `ctypes.GetVolumeInformationW`、`os.remove + 覆盖兜底`、`CREATE_NO_WINDOW` flag 这些 Windows 脏活已经被封进函数里了，你永远不用碰。

**依赖方向规则：**
```
高层 → 中层 → 底层
         ↓        ↓
      (中层可以直接 import 底层)
```

### 各层文件一览

| 层 | 文件 | 职责 | 依赖 |
|----|------|------|------|
| **底层** | `crypto.py` | 纯密码学原语（b64、HKDF、HMAC、AES-GCM、Ed25519、sha256） | 标准库 + cryptography |
| **底层** | `winops.py` | Windows 脏活（机器码、注册表、NTFS ADS、文件读写） | ctypes、winreg、crypto |
| **底层** | `ipc.py` | 子进程管道通信（Popen + CREATE_NO_WINDOW） | subprocess |
| **中层** | `state_store.py` | 三副本状态（文件+注册表+ADS）+ HMAC 完整性 + 取 max 合并 | crypto、winops |
| **中层** | `lic_token.py` | 三种令牌（LIC1/ULK1/REQ1）解析+验签 + 机器码 wrap_key | crypto、winops |
| **高层** | `verifier.py` | 独立验证进程：读状态 → 验卡密 → 更新状态 → 签响应 | crypto、ipc、state_store、lic_token、winops |
| **高层** | `activation.py` | 激活流程：生成请求码、导入卡密、定位卡密文件 | crypto、lic_token、runtime、winops |
| **高层** | `app.py` | 客户端主程序 + `authorize()` 接口 + 激活菜单 | activation、crypto、ipc、winops |
| **高层** | `game.py` | 示例业务（数字炸弹），授权通过后才被调用 | 标准库 |
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
    # result 是错误码，比如 "E_EXPIRED"、"签名无效"
    print(f"授权失败: {result}")
```

---

## 威胁模型

| # | 攻击手段 | 防御 |
|---|---------|------|
| 1 | 主程序里把 `if ok:` 改成 `if True` | verifier 只下发 ck 不下发布尔量；没有 ck 就没法解核心资源 |
| 2 | 卡密拷贝到另一台机器 | ck 用机器码派生的 wrap_key 包裹，目标机器以外 AES-GCM 认证失败 |
| 3 | 卡密 payload 被改、签了自己的 Ed25519 | 客户端只有公钥，没有私钥，签名伪造不了 |
| 4 | 系统时间回拨 | 三副本 `last` 字段取最大值；`now + 容忍窗口 < last` 即判作弊 |
| 5 | 删除状态文件/注册表/ADS 全部清零 | 三处必须同时还原；单点删不影响其他副本 |
| 6 | 多次试错爆破卡密 | `attempts` 计数 + 指数退避锁定（60s → 120s → 240s → 封顶 3600s） |
| 7 | verifier.exe 被替换成永远返回 ok 的桩 | app 启动前先验 verifier 的 Ed25519 签名；verifier 自己启动时也自验 |
| 8 | hook verifier 返回值伪造响应 | nonce 挑战 + 用 ck 签响应体做 HMAC；攻击者没有 ck 算不出正确 tag |

**明确不防的**：
- 机器码逆向：现在用 Nuitka 编译成机器码，产物里没有 `.py` 源码，但专业逆向人员仍可用 IDA / x64dbg 分析。成本从"几分钟读懂源码"变成"几小时读懂汇编"。
- 暴力穷举 ck（32 字节 AES 密钥，不可能）。
- 用调试器 hook `app.authorize()` / `winops.machine_id()` 等函数返回假值。要防这个，核心逻辑得用 C/Rust + 反调试 + 虚拟机混淆。
- **任何拿到一份有效卡密的人**：`mid` 明文写在 payload 里，`wrap_key_for(mid)` 的派生算法也是公开的，所以对方不需要厂商私钥、也不需要被授权的那台机器，就能解出 `content_key` 并解密 `payload.bin`。

> **开源后请先读这段**：本仓库以源码形式公开，上表是"设计意图"，不是安全承诺。
> 只要密钥或派生逻辑被写进客户端，它就不再是秘密。受此影响，第 2、4、5、6、8 条
> 目前均可被绕过（状态 HMAC 主密钥、ck 派生、响应 tag 都依赖客户端里"应该保密"的东西）。
> 修复方向见仓库 Issue。

---

## 文件清单

### 厂商侧（打包进 exe 的东西都不能有厂商私钥）

| 文件 | 作用 | 打包进 exe？ | 谁持有 |
|------|------|------------|--------|
| `keygen.py` | 厂商工具：init / mid / issue / sign-verifier / unlock-token / info | ❌ | 你 |
| `temp/vendor.key` | Ed25519 私钥，32 字节 seed | ❌ | 你（命门） |
| `vendor_pub.py` | 由 init 自动生成，含 `VENDOR_PUBKEY_B64`，需要提交 | ✅ | 客户 |
| `temp/content.key` | 32 字节固定内容密钥，init 时生成一次不再变 | ❌ | 你 |
| `temp/payload.bin` | AES-GCM 加密后的核心资源（init 时生成） | ✅ | 客户 |
| `build.py` | 一条命令 Nuitka 编译 + 签名流程 | ❌ | 你 |

**所有私密文件都在 `temp/` 里**：`temp/` 已被 `.gitignore` 忽略，开源前直接删掉整个目录即可，不会残留任何密钥或卡密。目录被删了也没关系，`keygen.py` 和客户端用到时会自动重建。

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

### 运行时状态（客户机器上，三处冗余）

| 位置 | 路径 | 备注 |
|------|------|------|
| 文件 | `%LOCALAPPDATA%\OfflineLicGuard\state.bin` | 最容易被注意到 |
| 注册表 | `HKCU\Software\OfflineLicGuard\s` | 普通用户不一定知道 |
| NTFS ADS | `<verifier.exe>:licstate` | 杀软敏感、复制/解压会丢 |

---

## 运行流程（时序）

```
客户启动 app.exe
     │
     ├─ ① app._check_verifier_authentic(verifier.exe)
     │     读 verifier.exe 算 SHA-256 → 读 verifier.exe.sig → Ed25519 公钥验签
     │     失败 → 返回 E_VERIFIER_INVALID，退出
     │
     ├─ ② 生成 32 字节 nonce
     │
     ├─ ③ ipc.run_request(verifier.exe, {"v":1, "nonce":"...", "lic":"<绝对路径>"})
     │     Popen verifier.exe，stdin 写 JSON + \n 分隔，stdout 读最后一行
     │     (CREATE_NO_WINDOW flag 永久焊死，不会弹黑窗)
     │
     ▼
  verifier.exe 启动
     │
     ├─ self_check() → 验自己的 SHA-256 签名
     │     失败 → 输出 E_SELF
     │
     ├─ StateStore.load() → 读三份副本 + HMAC 校验
     │     有副本验不过 → E_TAMPER
     │     lock_until > now → E_LOCKED
     │     now + tolerance < last → E_CLOCK + 锁
     │
     ├─ lic_token.verify_signed_token() → Ed25519 验 payload 签名
     │     失败 → 签名无效
     │
     ├─ lic_token.unwrap_content_key() → AES-GCM 解 ck（用 machine_id 派生的 wrap_key）
     │     失败 → 机器码不匹配
     │
     ├─ 过期 / 次数限制 → 已过期 / 次数耗尽
     │
     ├─ StateStore.save() → 三份副本（文件+注册表+ADS）
     │
     └─ 输出 {"ok":true, "ck":"...", "runs":..., "lim":..., "ts":..., "tag":"..."}
          tag = HMAC(ck, nonce + canonical(resp_without_tag))
     │
     ▼
  app.exe 读响应
     │
     ├─ 失败响应 → 按 code 映射为用户友好提示
     │
     ├─ HMAC 验 tag（用响应里的 ck + 请求里的 nonce 重算）
     │     失败 → E_TAG
     │
     └─ crypto.aes_gcm_decrypt(ck, payload.bin) → 核心资源明文
          ck 不对 → InvalidTag，没任何有价值内容
```

---

## 协议（v=1）

### 请求
```json
{
  "v": 1,
  "nonce": "abcdef...（32 字节随机数的 hex 字符串）",
  "lic": "C:\\path\\to\\license.lic"
}
```

### 成功响应
```json
{
  "v": 1,
  "ok": true,
  "ck": "<内容密钥 base64>",
  "runs": 3,
  "lim": 0,
  "ts": 1732740000,
  "tag": "<HMAC-SHA256(ck, nonce + canonical({v,ok,ck,runs,lim,ts})) 的 base64>"
}
```

### 失败响应
```json
{"v": 1, "ok": false, "code": "E_EXPIRED", "ts": 1732740000}
```

错误码映射：

| code | 含义 | 触发位置 |
|------|------|---------|
| E_SELF | verifier 自校验失败 | verifier.self_check() |
| E_REQ | 请求格式错 / 协议版本不匹配 | verifier.main() |
| E_TAMPER | 状态有副本被改坏 | StateStore.load() |
| E_LOCKED | 仍在锁定窗口内 | verifier.handle() |
| E_CLOCK | 系统时间被回拨 | verifier.handle() |
| E_LIC_READ | 卡密文件不存在或读不到 | verifier.handle() |
| E_TAG | 主程序收到的响应 tag 对不上 | app._ask_verifier() |
| E_VERIFIER_INVALID | verifier.exe 的 Ed25519 签名无效 | app._check_verifier_authentic() |
| E_DECRYPT | payload.bin 解密失败 | app._load_core() |

注意：卡密本身的签名/机器码/过期/次数错误是**中文消息**直接返回的（"签名无效"、"机器码不匹配"、"已过期"、"次数耗尽"），不是 E_XXX 格式。

---

## 卡密格式

顶层是 `LIC1.<payload_b64>.<Ed25519_signature_b64>`，三段。

payload JSON：
```json
{
  "v": 1,
  "lid": "0ba1b22692f48c69",
  "mid": "4dc5a1cb3e55e251...（64 位 hex 机器码）",
  "iat": 1732740000,
  "exp": 1797479947,
  "runs": 0,
  "feat": ["pro"],
  "ck": "9-3vi4hKI7KYZD0sfLD98_fion..."
}
```

其中 `ck` 字段是**内容密钥的密文**：
```
nonce(12字节) || AES-GCM(wrap_key_for(mid), content_key, aad="ck-wrap")
```

`wrap_key_for(mid)` = HKDF(bytes.fromhex(mid), "lic-wrap-v1", "content-key")

`content_key` 就是 `content.key` 文件里的 32 字节，init 时生成一次就固定。**换机器** → HKDF 输出不同 → AES-GCM 认证标签不匹配 → ck 解不开。

签名 = `Ed25519_private_sign(crypto.canonical(payload))`。客户端只有公钥，没法伪造签名。

---

## 状态字典字段

三副本里存的就是这个 dict，HMAC 做完整性保护。

| 字段 | 类型 | 含义 |
|------|------|------|
| `lid` | str | 当前验证过的卡密唯一 ID |
| `first` | int | 第一次验证成功的时间戳（秒） |
| `last` | int | 三副本里见过的最大时间戳。`now + 容忍 < last` 即判回拨 |
| `runtime` | int | 累计在线时长（秒）。当前版本只累加不减，可改成预算扣减模型 |
| `runs` | int | 累计运行次数。和卡密 `runs` 字段（上限）对比 |
| `attempts` | int | 连续错误次数。达 MAX_ATTEMPTS_BEFORE_LOCK=3 后进入指数退避 |
| `lock_until` | int | 临时锁定到期时间戳。在此之前所有请求直接拒 |

**合并规则**：三副本里每个整数字段取**最大值**。这样：
- 攻击者把某副本的 `runs` 改小 → 取 max 仍是真实累计次数；
- 攻击者把某副本的 `last` 改小 → 不影响回拨检测；
- 把某个副本改成垃圾数据 → 那个副本的 HMAC 通不过 → `tampered=True` → E_TAMPER。

**HMAC 密钥**：拆成三段 hex 写死在源码里，运行时异或还原，再 HKDF 派生成真正的 MAC key。防止 strings/grep 直接搜到完整密钥。

---

## 签发一条龙（厂商操作流程）

```bash
# === 第一次：初始化密钥（只做一次，永久有效） ===
cd licguard
python keygen.py init
# 生成 temp/vendor.key / vendor_pub.py / temp/content.key / temp/payload.bin

# === 每次给新客户发货 ===
# 1. 编译客户端（默认不带卡密，客户装上是"未激活"状态）
python build.py
#    调试时加 --with-license 可把 temp/license.lic 一起带进 dist/temp

# 2. 打安装包（可选，见 installer/setup.iss）
#    发给客户的就是 installer/output/Setup_*.exe

# 3. 客户装好后第一次运行 → 看到激活菜单
#    客户选 1 → 生成 REQ1 请求码 → 发给厂商

# 4. 收到请求码后签发卡密
python keygen.py issue --request "REQ1.xxx" --days 365 --runs 0
#    默认写到 temp/license.lic

#    不想记参数就用交互式工具：
python sign.py
#    支持：粘贴请求码 / 选文件 / 直接输入机器码 / 更换私钥文件
#    签完自动复制卡密到剪贴板

# 5. 把卡密内容（或文件）发给客户
#    客户在菜单里选 2 粘贴导入 → 进入使用

# 也可以跳过请求码，直接凭机器码签发：
python keygen.py issue --mid 4dc5a1cb... --days 365 --runs 0
```

### 客户首次激活流程（客户视角）

```
双击 app.exe
   ↓
没有卡密 → 显示菜单
   1) 生成激活请求码（发给厂商）
   2) 导入厂商发回的卡密
   0) 退出
   ↓ 选 1
生成 REQ1，同时保存到 temp/request.txt，并把整行显示出来
   ↓ 客户复制发给你
   ↓ 你跑 keygen.py issue --request ...，把卡密发回
   ↓ 客户选 2，粘贴卡密
验证通过 → 写入 temp/license.lic → 进入程序
下次启动直接读取 temp/license.lic，不再弹菜单
```

**注意**：
- 重建密钥（`keygen.py init --reset`）会让**所有已签发的卡密失效**——旧卡密的 Ed25519 签名验不过新私钥对应的公钥。
- `build.py` 每次重新编译 verifier.exe 后会自动用 vendor.key 给它签名。**签完名的 exe 不能再改**——哪怕改一个字节，verifier 自己的 self_check 和 app 的 _check_verifier_authentic 都会过不了。

---

## 解除锁定流程（reset.py + keygen.py unlock-token）

客户那边被锁了（E_LOCKED / E_CLOCK / E_TAMPER），但你是合法厂商，可以用签名重置令牌来帮他解锁。

### 安全设计

`reset.py`（和 app.py / verifier.py 一样打包发给客户）**没有厂商私钥**。所以它自身什么都做不了——必须吃一张由 `keygen.py unlock-token` 用厂商私钥签好的重置令牌（`ULK1.` 前缀）才能生效。这意味着：

- 令牌只能在**绑定的那台机器**上用（mid 不匹配会被拒绝）；
- 令牌可以带过期时间（`--ttl`），防止旧令牌被重复利用；
- 令牌的 Ed25519 签名客户端只有公钥，伪造不了。

### 重置三种模式

| 模式 | 清理内容 | 适用场景 |
|------|---------|---------|
| `unlock` | 只清 `lock_until` | 单纯因为系统时间被调了导致的临时锁定 |
| `attempts` | 清 `attempts` + `lock_until` | 客户试了几次错卡密被锁定，允许再试 |
| `full` | 三副本全部清空 | 状态被篡改（E_TAMPER），或者客户换了机器 |

### 客户侧（本机）
```bash
python reset.py request --mode attempts
# 输出会类似：
# 重置请求码（发给厂商）：
# REQ1.eyJtaWQiOiI0ZGM1YTFj...
# 当前状态摘要：tampered=False  lock_until=1732740330  attempts=4
```

### 厂商侧（你这边）
```bash
# 吃客户发回来的请求码，签成正式重置令牌
python keygen.py unlock-token --request REQ1.eyJtaWQiOiI...

# 或者直接给 mid，跳过请求码这一步（不影响安全）
python keygen.py unlock-token --mid 4dc5a1cb... --mode attempts
```

### 客户侧（再发回）
```bash
python reset.py apply --token ULK1.eyJleHAiOjAsImlhdCI6...
# 输出：[成功] 已清 attempts + lock_until
```

### tampered 状态降级

如果 `StateStore.load()` 返回 `tampered=True`（三副本里有副本 HMAC 通不过），`reset.py` 会**忽略你指定的 mode**，直接把三个落点全部清空。理由：被篡改过的状态不可信，在它上面再做字段级修改只会让状态更混乱。

---

## 底层函数速查（方便以后自己改）

### crypto.py
| 函数 | 做什么 |
|------|--------|
| `b64e(data)` / `b64d(text)` | URL-safe base64 编解码，自动处理 padding |
| `canonical(obj)` | JSON 序列化成稳定字节串（key 排序、无空格、UTF-8），签名前必调 |
| `hkdf(key, salt, info, length=32)` | HKDF-SHA256 密钥派生 |
| `hmac_sha256(key, msg)` / `hmac_equals(a, b)` | HMAC-SHA256 + 常量时间比较 |
| `aes_gcm_encrypt(key, pt, nonce, aad=b"")` / `aes_gcm_decrypt(...)` | AES-GCM 带认证的加解密 |
| `ed25519_sign(priv, msg)` / `ed25519_verify(pub, sig, msg)` | Ed25519 签名验签（verify 返回 bool，不抛异常） |
| `ed25519_keygen()` | 生成 (priv_32bytes, pub_32bytes) |
| `sha256(data)` / `sha256_hex(data)` | SHA-256（字节版 / hex 版） |

### winops.py
| 函数 | 做什么 |
|------|--------|
| `machine_id()` | 64 位 hex 机器指纹（卷序列号 + MachineGuid 的 sha256） |
| `reg_write(path, name, value)` / `reg_read(...)` / `reg_delete(...)` | HKCU\Software 下的注册表读写删 |
| `ads_write(file, stream, data)` / `ads_read(...)` / `ads_delete(...)` | NTFS ADS 备用数据流读写删（delete 有覆盖兜底） |
| `file_write/read/delete(path)` | 普通文件操作 |

### ipc.py
| 函数 | 做什么 |
|------|--------|
| `run_request(exe, request_dict, timeout=15)` | 启动子进程，stdin 发 JSON，stdout 收最后一行 JSON，自动 CREATE_NO_WINDOW |
| `run_line(exe, stdin_text, timeout=15)` | 简单版：stdin 给文本，返回 stdout 全文 |

---

## 已知限制

### 1. 编译成机器码，挡得住反编译，挡不住逆向

现在用 Nuitka 把 Python 编译成 C 再编译成机器码，产物里没有 `.py` / `.pyc`：

| | PyInstaller（旧方案） | Nuitka（现在） |
|---|---|---|
| 产物内容 | 字节码 + 解释器 | 机器码 |
| 还原源码 | pyinstxtractor 几分钟搞定 | 拿不到 |
| 改逻辑 | 改 `.py` 重新打包 | 需要 patch 机器码 |

但这不等于"不可破"：`_master_secret()`、`machine_id()` 这类逻辑仍可被 IDA / x64dbg 定位，只是从"读懂 Python"变成"读懂汇编再打补丁"，成本高一个数量级。

**继续加固的方向**：核心逻辑用 C/Rust 手写、加反调试、保持版本更新。

### 2. 杀软误报

Nuitka 输出的是常规 PE 文件 + 依赖 DLL，不再是自解压单文件，启发式误报会比 onefile 少。但下面这些行为仍可能触发检测：
- 往 verifier.exe 写 ADS（NTFS 备用数据流）→ Defender/360 可能拦；
- 写注册表 HKCU → 正常行为但叠加后更敏感；
- 读系统盘卷序列号 → 也可能触发启发式。

**缓解措施**：
- 用 EV 代码签名证书签名 exe（最有效）；
- 不要再给 dist 里的 exe 加 UPX 之类的壳；
- 把 ADS 副本改成单独文件，降低被杀软标记为"可疑"的概率；
- 上线前向微软安全响应中心和 360 提交误报申诉。

### 3. 离线场景最终可破

任何没联网的卡密系统，攻击者只要**拿到一个有效卡密并能逆向**，最终都能破。能做的是把成本从"改一个跳转"抬到"必须手握一份有效卡密 + 逆向 verifier"。当前设计已经到后者的门槛。

### 4. 状态三副本可被全部删除

攻击者手动删掉三个落点（文件、注册表、ADS），状态就回到初始全 0。三副本的设计目的不是"防住"，而是让攻击者**必须同时找到并删除三个位置**——普通用户不一定知道 ADS 这回事。

如果卡密是"总运行次数"卖的，建议再加一层**用量预算**模型：签发卡密时就把可运行时长拆成若干"块"，每跑一次消耗一块，块的消耗记录写进状态三副本。这样就算状态全删、次数清零，**已消耗的块数也无法被补回**，因为块的签名写死在卡密 payload 里。

### 5. ADS 删除"假成功"的历史问题

早期版本里 `os.remove()` 和 `DeleteFileW` 对 PyInstaller 打包的 exe 上的 ADS 会返回 True 但流实际还在。现在 `winops.ads_delete()` 里加了覆盖兜底——删不掉就用 `\x00` 覆盖 32 字节，上层 `StateStore.load()` 的 HMAC 校验会判定 tampered=True，自然触发重置。这个 bug 已修，留在文档里是为了万一以后要移植到别的打包器时别踩同样的坑。
