"""高层：keygen.py —— 厂商侧工具。

私钥只在这里，绝不打包进 exe。五个子命令：
  init            生成密钥对 + 内容密钥 + payload.bin（一次性）
  mid             打印某台机器的机器码
  issue           签发卡密
  sign-verifier   给 verifier.exe 加自校验签名
  unlock-token    签发重置令牌（客户被锁后解用）
  info            本地验卡密签名 + 打印 payload
"""
import argparse
import json
import os
import secrets
import sys
import time

import crypto
import lic_token as tk
import winops
from vendor_pub import VENDOR_PUBKEY_B64


HERE = os.path.dirname(os.path.abspath(__file__))
# 所有私密数据都放 temp/：开源前删掉这个目录就不会泄露密钥
TEMP = os.path.join(HERE, "temp")
PRIV_PATH = os.path.join(TEMP, "vendor.key")
CONTENT_PATH = os.path.join(TEMP, "content.key")
PAYLOAD_PATH = os.path.join(TEMP, "payload.bin")
# 公钥要给 exe 用，必须留在根目录被 import
PUB_MODULE = os.path.join(HERE, "vendor_pub.py")


def _ensure_temp() -> None:
    """temp/ 被删掉后能自动重建。"""
    os.makedirs(TEMP, exist_ok=True)

DEMO_CONTENT = """核心资源：这份内容本身是加密的，密钥由 verifier 在校验通过后下发。
把主程序里"如果验证失败就退出"的那句判断改掉，也只能得到乱码，
因为解密密钥压根不存在于主程序中。"""


def _load_priv(path: str | None = None) -> bytes:
    with open(path or PRIV_PATH, "rb") as f:
        return f.read()


# ================================================================
# init
# ================================================================

def cmd_init(args) -> None:
    _ensure_temp()
    if os.path.exists(PRIV_PATH) and not args.reset:
        print("已存在 vendor.key，如需重建请加 --reset（旧卡密将全部失效）")
        return

    priv_bytes, pub_bytes = crypto.ed25519_keygen()
    open(PRIV_PATH, "wb").write(priv_bytes)
    open(PUB_MODULE, "w", encoding="utf-8").write(
        f'"""由 keygen.py init 自动生成，勿手改。"""\n'
        f'VENDOR_PUBKEY_B64 = "{crypto.b64e(pub_bytes)}"\n'
    )

    ck = secrets.token_bytes(32)
    open(CONTENT_PATH, "wb").write(ck)
    nonce = secrets.token_bytes(12)
    open(PAYLOAD_PATH, "wb").write(nonce + crypto.aes_gcm_encrypt(ck, DEMO_CONTENT.encode(), nonce, b"payload-v1"))

    print("已生成：temp/vendor.key（私钥，勿外发）/ vendor_pub.py / temp/content.key / temp/payload.bin")


# ================================================================
# mid
# ================================================================

def cmd_mid(_args) -> None:
    print(winops.machine_id())


# ================================================================
# issue
# ================================================================

def cmd_issue(args) -> None:
    priv = _load_priv(args.key)
    ck = open(CONTENT_PATH, "rb").read()

    # 两种签发方式：直接给机器码，或者丢一段客户发来的 REQ1 请求码
    if args.request:
        try:
            req, _, _ = tk.parse_token(args.request, "REQ1")
            mid = str(req["mid"]).lower()
        except (tk.TokenError, KeyError) as e:
            sys.exit(f"请求码格式错: {e}")
    else:
        mid = args.mid.strip().lower()

    payload = {
        "v": 1,
        "lid": secrets.token_hex(8),
        "mid": mid,
        "iat": int(time.time()),
        "exp": int(time.time()) + args.days * 86400 if args.days else 0,
        "runs": args.runs,
        "feat": ["pro"],
        "ck": tk.wrap_content_key(ck, mid),
    }
    lic = tk.sign_token(payload, "LIC1", priv)

    out = args.out or os.path.join(TEMP, "license.lic")
    _ensure_temp()
    with open(out, "w", encoding="utf-8") as f:
        f.write(lic)
    print(f"已签发 {out}  lid={payload['lid']}  mid={mid[:12]}…  days={args.days}  runs={args.runs or '不限'}")


# ================================================================
# sign-verifier
# ================================================================

def cmd_sign_verifier(args) -> None:
    priv = _load_priv()
    data = open(args.exe, "rb").read()
    digest = crypto.sha256_hex(data).encode()
    sig = crypto.ed25519_sign(priv, digest)
    with open(args.exe + ".sig", "w", encoding="utf-8") as f:
        f.write(crypto.b64e(sig))
    print(f"已签名 {args.exe}  sha256={digest.decode()}")


# ================================================================
# unlock-token
# ================================================================

def cmd_unlock_token(args) -> None:
    priv = _load_priv()

    if args.request:
        try:
            payload, _, _ = tk.parse_token(args.request, "REQ1")
            mid = payload["mid"]
            mode = args.mode or payload.get("mode", "unlock")
        except tk.TokenError as e:
            sys.exit(f"请求码格式错: {e}")
    else:
        mid = args.mid.strip().lower()
        mode = args.mode or "unlock"

    if mode not in ("unlock", "attempts", "full"):
        sys.exit("mode 必须是 unlock / attempts / full")

    payload = {
        "v": 1,
        "mid": mid,
        "mode": mode,
        "iat": int(time.time()),
        "exp": int(time.time()) + (args.ttl or 3600) if args.ttl else 0,
        "nonce": crypto.b64e(secrets.token_bytes(12)),
    }
    token = tk.sign_token(payload, "ULK1", priv)

    if args.out:
        open(args.out, "w", encoding="utf-8").write(token)
        print(f"已签发 → {args.out}")
    else:
        print(token)
    print(f"  mid={mid}  mode={mode}  ttl={args.ttl or '永不过期'}s")


# ================================================================
# info
# ================================================================

def cmd_info(args) -> None:
    text = open(args.lic, "r", encoding="utf-8").read()
    try:
        payload = tk.verify_signed_token(text, "LIC1", VENDOR_PUBKEY_B64)
        print("签名有效")
    except tk.TokenError as e:
        print(f"签名无效: {e}")
        payload, _, _ = tk.parse_token(text, "LIC1")
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def main() -> None:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init")
    s.add_argument("--reset", action="store_true")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("mid")
    s.set_defaults(func=cmd_mid)

    s = sub.add_parser("issue")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--mid", help="客户的机器码")
    g.add_argument("--request", help="客户发来的 REQ1 请求码")
    s.add_argument("--days", type=int, default=30)
    s.add_argument("--runs", type=int, default=0)
    s.add_argument("--out", help="默认写到 temp/license.lic")
    s.add_argument("--key", help="私钥文件，默认 temp/vendor.key")
    s.set_defaults(func=cmd_issue)

    s = sub.add_parser("sign-verifier")
    s.add_argument("--exe", required=True)
    s.set_defaults(func=cmd_sign_verifier)

    s = sub.add_parser("unlock-token")
    s.add_argument("--mid")
    s.add_argument("--request")
    s.add_argument("--mode", default="unlock", choices=["unlock", "attempts", "full"])
    s.add_argument("--ttl", type=int, default=0)
    s.add_argument("--out")
    s.set_defaults(func=cmd_unlock_token)

    s = sub.add_parser("info")
    s.add_argument("--lic", required=True)
    s.set_defaults(func=cmd_info)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
