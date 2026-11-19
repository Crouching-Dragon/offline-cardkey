"""高层：reset.py —— 解除程序。

**没有厂商私钥**，自身什么都做不了——必须吃一张由 keygen.py unlock-token
签好的 ULK1 令牌才能生效。

两种用法：
  --request   在本机生成 REQ1 请求码（含 mid + 状态摘要），发给厂商
  --apply     消费厂商签好的 ULK1 令牌
"""
import argparse
import json
import secrets
import sys
import time

import crypto
import state_store as ss
import lic_token as tk
import winops
from vendor_pub import VENDOR_PUBKEY_B64


def cmd_request(_args) -> None:
    """生成本机重置请求码，客户发给厂商。"""
    mid = winops.machine_id()
    store = ss.StateStore()
    state, tampered = store.load()

    body = json.dumps(state, sort_keys=True, ensure_ascii=False).encode()
    digest = crypto.sha256_hex(body + (b"tampered" if tampered else b"ok"))

    payload = {
        "v": 1,
        "mid": mid,
        "mode": _args.mode or "unlock",
        "state_digest": digest,
        "ts": int(time.time()),
        "nonce": secrets.token_hex(16),
    }
    print("重置请求码（发给厂商）：")
    print(f"REQ1.{crypto.b64e(crypto.canonical(payload))}")
    print(f"\n当前状态摘要:")
    print(f"  tampered   = {tampered}")
    print(f"  lock_until = {state.get('lock_until', 0)}")
    print(f"  attempts   = {state.get('attempts', 0)}")
    print(f"  runs       = {state.get('runs', 0)}")
    print(f"  digest     = {digest[:16]}...")


def cmd_apply(args) -> None:
    """消费厂商签发的 ULK1 令牌。"""
    text = args.token
    if args.file:
        text = open(args.file, "r", encoding="utf-8").read()

    try:
        payload = tk.verify_unlock_token(text, VENDOR_PUBKEY_B64, winops.machine_id())
    except tk.TokenError as e:
        print(f"[失败] {e}")
        sys.exit(1)

    mode = payload["mode"]
    store = ss.StateStore()

    state, tampered = store.load()

    # tampered → 忽略 mode，直接全清
    if tampered or mode == "full":
        store.clear()  # 三副本全清（StateStore 内部已正确定位 verifier.exe 上的 ADS）
        if tampered:
            print("[注意] 检测到状态被篡改，已清空三副本")
        else:
            print("[成功] 已清空三副本状态（full 模式）")
        return

    # unlock / attempts：读状态，改字段，写回
    state["lock_until"] = 0
    if mode == "attempts":
        state["attempts"] = 0
        print("[成功] 已清 attempts + lock_until")
    else:
        print("[成功] 已清 lock_until（unlock 模式）")
    store.save(state)


def main() -> None:
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    p = argparse.ArgumentParser(description="licguard 解除程序（需厂商签发的令牌）")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("request")
    s.add_argument("--mode", default="unlock", choices=["unlock", "attempts", "full"])
    s.set_defaults(func=cmd_request)

    s = sub.add_parser("apply")
    src = s.add_mutually_exclusive_group(required=True)
    src.add_argument("--token")
    src.add_argument("--file")
    s.set_defaults(func=cmd_apply)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
