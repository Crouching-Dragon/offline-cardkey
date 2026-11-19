"""高层：verifier.exe —— 独立授权验证进程。

主程序（app.exe）通过 stdin 管道发请求进来，这里只做一件事：
  读状态 → 验卡密 → 更新状态 → 下发内容密钥

响应协议 v2：成功响应由本机 Ed25519 私钥签名，app 用卡密里（厂商签过）
的机器公钥验签。签名密钥不在响应里，所以伪造响应拿不到正确签名。
"""
import json
import sys
import time

import crypto
import machine_key
import runtime
import state_store as ss
import lic_token as tk
import winops
from vendor_pub import VENDOR_PUBKEY_B64

PROTO_VERSION = 2
CLOCK_TOLERANCE = 300                 # NTP 微调容忍窗口（秒）
MAX_ATTEMPTS_BEFORE_LOCK = 3          # 连续错误达此数后进入指数退避
MAX_REQUEST_CHARS = 65536


# ================================================================
# 自校验 —— 防止 exe 被替换成桩
# ================================================================

def self_check() -> bool:
    """打包后用厂商公钥验 verifier.exe 的 SHA-256。开发态跳过。"""
    if not runtime.is_compiled():
        return True
    exe = winops.current_exe()
    sig_text = winops.file_read(exe + ".sig")
    data = winops.file_read(exe)
    if sig_text is None or data is None:
        return False
    digest = crypto.sha256_hex(data).encode()
    return crypto.ed25519_verify(
        crypto.b64d(VENDOR_PUBKEY_B64),
        crypto.b64d(sig_text.decode().strip()),
        digest,
    )


# ================================================================
# 主验证流程
# ================================================================

def backoff_seconds(attempts: int) -> int:
    """指数退避：3 次内不锁，之后 60→120→240→…→封顶 3600 秒。"""
    if attempts < MAX_ATTEMPTS_BEFORE_LOCK:
        return 0
    return min(60 * (2 ** (attempts - MAX_ATTEMPTS_BEFORE_LOCK)), 3600)


def verify_and_update(lic_text: str, store: ss.StateStore, now: int) -> dict:
    """核心验证 + 状态更新。失败抛 PermissionError / TokenError。"""
    state, tampered = store.load()
    if tampered:
        raise PermissionError("E_TAMPER")
    if int(state.get("lock_until", 0)) > now:
        raise PermissionError("E_LOCKED")

    last = int(state.get("last", 0))
    if last and now + CLOCK_TOLERANCE < last:
        state["attempts"] = int(state.get("attempts", 0)) + 1
        # 锁到期时间要基于"见过的最新时间"，否则把时钟调回来就能绕过
        state["lock_until"] = max(last, now) + max(backoff_seconds(state["attempts"]), 60)
        store.save(state)
        raise PermissionError("E_CLOCK")

    mid = winops.machine_id()
    payload, ck = tk.verify_license(
        lic_text, mid,
        machine_key.enc_private(),
        VENDOR_PUBKEY_B64,
        machine_key.sign_public_b64(),
    )

    max_runs = int(payload.get("runs", 0) or 0)
    if max_runs and int(state.get("runs", 0)) >= max_runs:
        raise PermissionError("E_RUNS")

    elapsed = max(0, now - last) if last else 0
    state["lid"] = payload.get("lid", "")
    state["first"] = int(state.get("first", 0)) or now
    state["last"] = max(last, now)
    state["runtime"] = int(state.get("runtime", 0)) + elapsed
    state["runs"] = int(state.get("runs", 0)) + 1
    state["attempts"] = 0
    state["lock_until"] = 0
    store.save(state)

    return {
        "v": PROTO_VERSION,
        "ok": True,
        "ck": crypto.b64e(ck),
        "runs": state["runs"],
        "lim": max_runs,
        "ts": now,
    }


def handle(request: dict) -> dict:
    """处理一次验证请求（高层入口）。"""
    now = int(time.time())

    nonce_hex = request.get("nonce", "")
    if not isinstance(nonce_hex, str) or not (32 <= len(nonce_hex) <= 128):
        return fail("E_REQ")
    try:
        bytes.fromhex(nonce_hex)
    except ValueError:
        return fail("E_REQ")

    lic_path = request.get("lic", "")
    if not isinstance(lic_path, str) or not lic_path or len(lic_path) > 4096:
        return fail("E_REQ")
    try:
        with open(lic_path, "r", encoding="utf-8") as f:
            lic_text = f.read(MAX_REQUEST_CHARS)
    except OSError:
        return fail("E_LIC_READ")

    store = ss.StateStore()
    try:
        with store.lock():
            try:
                resp = verify_and_update(lic_text, store, now)
            except PermissionError as e:
                code = str(e)
                # 失败 → attempts+1，可能触发锁定（锁定/篡改/回拨/次数耗尽本身不重复计数）
                if code not in ("E_LOCKED", "E_TAMPER", "E_CLOCK", "E_RUNS"):
                    state, _ = store.load()
                    state["attempts"] = int(state.get("attempts", 0)) + 1
                    state["lock_until"] = now + backoff_seconds(state["attempts"])
                    store.save(state)
                return fail(code)
            except tk.TokenError as e:
                return fail(str(e))

            # 给响应签名：密钥只在本机 DPAPI 里，响应体里不出现
            resp["nonce"] = nonce_hex
            body = {k: v for k, v in resp.items() if k != "sig"}
            resp["sig"] = crypto.b64e(machine_key.sign(crypto.canonical(body)))
            return resp
    except TimeoutError:
        return fail("E_BUSY")
    except RuntimeError:
        # machine_key 生成/解封失败（DPAPI 不可用等）
        return fail("E_MACHINE_KEY")
    except Exception:
        return fail("E_INTERNAL")


def fail(code: str) -> dict:
    return {"v": PROTO_VERSION, "ok": False, "code": code, "ts": int(time.time())}


def main() -> None:
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    if not self_check():
        print(json.dumps(fail("E_SELF"), ensure_ascii=False), flush=True)
        return

    line = sys.stdin.readline(MAX_REQUEST_CHARS)
    if not line or len(line) >= MAX_REQUEST_CHARS:
        print(json.dumps(fail("E_REQ"), ensure_ascii=False), flush=True)
        return
    try:
        req = json.loads(line)
        if not isinstance(req, dict) or int(req.get("v", 0)) != PROTO_VERSION:
            raise ValueError
    except Exception:
        print(json.dumps(fail("E_REQ"), ensure_ascii=False), flush=True)
        return

    resp = handle(req)
    print(json.dumps(resp, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
