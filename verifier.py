"""高层：verifier.exe —— 独立授权验证进程。

主程序（app.exe）通过 stdin 管道发请求进来，这里只做一件事：
  读状态 → 验卡密 → 更新状态 → 下发内容密钥

任何校验失败都统一成 E_XXX 错误码返回，不下发布尔值。
"""
import json
import secrets
import sys
import time

import crypto
import runtime
import state_store as ss
import lic_token as tk
import winops
from vendor_pub import VENDOR_PUBKEY_B64

PROTO_VERSION = 1
CLOCK_TOLERANCE = 300                 # NTP 微调容忍窗口（秒）
MAX_ATTEMPTS_BEFORE_LOCK = 3          # 连续错误达此数后进入指数退避


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
    """核心验证 + 状态更新。

    输入：卡密文本、StateStore、当前时间戳
    输出：成功的完整响应 dict 或 raise TokenError/其他异常
    """
    state, tampered = store.load()
    if tampered:
        raise PermissionError("E_TAMPER")
    if int(state.get("lock_until", 0)) > now:
        raise PermissionError("E_LOCKED")

    # 回拨检测：三副本 max(last) 比当前还新 → 系统时钟被往前调过
    last = int(state.get("last", 0))
    if last and now + CLOCK_TOLERANCE < last:
        state["attempts"] = int(state.get("attempts", 0)) + 1
        state["lock_until"] = now + max(backoff_seconds(state["attempts"]), 60)
        store.save(state)
        raise PermissionError("E_CLOCK")

    mid = winops.machine_id()
    payload, ck = tk.verify_license(lic_text, mid, VENDOR_PUBKEY_B64)

    # 次数限制
    max_runs = int(payload.get("runs", 0))
    if max_runs and int(state.get("runs", 0)) >= max_runs:
        raise PermissionError("E_RUNS")

    # 全部通过 → 更新状态
    state["lid"] = payload.get("lid", "")
    state["first"] = int(state.get("first", 0)) or now
    state["last"] = max(last, now)
    state["runtime"] = int(state.get("runtime", 0)) + max(0, int(time.time()) - now)
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
    store = ss.StateStore()
    lic_path = request.get("lic", "")

    try:
        with open(lic_path, "r", encoding="utf-8") as f:
            lic_text = f.read()
    except OSError:
        return fail("E_LIC_READ")

    try:
        resp = verify_and_update(lic_text, store, now)
    except PermissionError as e:
        code = str(e)
        # 失败 → attempts+1，可能触发锁定（E_LOCKED 本身不计数）
        if code not in ("E_LOCKED", "E_TAMPER", "E_CLOCK"):
            state, _ = store.load()
            state["attempts"] = int(state.get("attempts", 0)) + 1
            state["lock_until"] = now + backoff_seconds(state["attempts"])
            store.save(state)
        return fail(code)
    except tk.TokenError as e:
        return fail(str(e))
    except Exception:
        return fail("E_INTERNAL")

    # 给响应签上 HMAC：主程序用 ck + 请求里的 nonce 重算验签
    nonce = bytes.fromhex(request.get("nonce", ""))
    body_without_tag = {k: v for k, v in resp.items() if k != "tag"}
    resp["tag"] = crypto.b64e(
        crypto.hmac_sha256(crypto.b64d(resp["ck"]), nonce + crypto.canonical(body_without_tag))
    )
    return resp


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
    try:
        req = json.loads(sys.stdin.readline())
        if int(req.get("v", 0)) != PROTO_VERSION:
            raise ValueError
    except Exception:
        print(json.dumps(fail("E_REQ"), ensure_ascii=False), flush=True)
        return
    resp = handle(req)
    print(json.dumps(resp, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
