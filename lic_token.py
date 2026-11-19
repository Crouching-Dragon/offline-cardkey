"""中层：卡密 + 重置令牌 + 机器绑定（协议 v2）。

统一处理三种令牌格式：
  LIC1.<payload_b64>.<sig_b64>   —— 签发的卡密（Ed25519 签）
  ULK1.<payload_b64>.<sig_b64>   —— 签发的重置令牌（Ed25519 签）
  REQ1.<payload_b64>             —— 客户发给厂商的请求码（无签名）

机器绑定（v2）：客户首次运行时生成一对 X25519 密钥（私钥由 DPAPI 保护），
REQ1 把公钥带给厂商；厂商签发卡密时用这把公钥封装 content_key。
换机器 / 换 Windows 用户 → 私钥不同 → AES-GCM 解不开，且卡密里没有任何
可以用来复现私钥的公开数据。
"""
import json
import secrets
import time

import crypto

# 封装参数（换版本时改这里即可让旧格式自然失效）
WRAP_SALT = b"lic-wrap-v2"
WRAP_INFO = b"content-key"
WRAP_AAD = b"ck-wrap-v2"

MAX_TOKEN_CHARS = 65536


class TokenError(Exception):
    """令牌解析/验签失败时抛的统一异常。"""
    pass


# ================================================================
# 机器绑定 —— 用机器 X25519 公钥封装 content_key
# ================================================================

def wrap_content_key(content_key: bytes, machine_pub_b64: str) -> dict:
    """厂商侧：把内容密钥封装给某台机器的 X25519 公钥。

    返回 {"epk": 临时公钥, "ck": nonce||密文}，两个字段都进签名 payload。
    私钥只存在于客户机器的 DPAPI 里，厂商也不需要知道。
    """
    try:
        machine_pub = crypto.b64d(machine_pub_b64)
    except Exception:
        raise TokenError("机器公钥不是合法 base64")
    if len(machine_pub) != 32:
        raise TokenError("机器公钥长度不对")

    eph_priv, eph_pub = crypto.x25519_keygen()
    shared = crypto.x25519_exchange(eph_priv, machine_pub)
    key = crypto.hkdf(shared, WRAP_SALT, WRAP_INFO)
    nonce = secrets.token_bytes(12)
    ct = crypto.aes_gcm_encrypt(key, content_key, nonce, WRAP_AAD)
    return {"epk": crypto.b64e(eph_pub), "ck": crypto.b64e(nonce + ct)}


def unwrap_content_key(payload: dict, machine_enc_priv: bytes) -> bytes:
    """客户端侧：用本机 X25519 私钥解开卡密里的 content_key。

    失败都是 AES-GCM InvalidTag：机器公钥不匹配、ck/epk 被改、aad 不对。
    """
    try:
        epk = crypto.b64d(str(payload.get("epk", "")))
        blob = crypto.b64d(str(payload.get("ck", "")))
    except Exception:
        raise TokenError("卡密缺少机器封装数据")
    if len(epk) != 32 or len(blob) < 12 + 16:
        raise TokenError("卡密缺少机器封装数据")

    shared = crypto.x25519_exchange(machine_enc_priv, epk)
    key = crypto.hkdf(shared, WRAP_SALT, WRAP_INFO)
    return crypto.aes_gcm_decrypt(key, blob[12:], blob[:12], WRAP_AAD)


# ================================================================
# 统一的令牌解析
# ================================================================

def parse_token(text: str, expected_prefix: str,
                parts_required: int | None = None) -> tuple[dict, bytes, bytes | None]:
    """拆分令牌 → (payload_dict, payload_raw_bytes, signature_or_None)。

    REQ1 只有两段；LIC1 / ULK1 必须三段。格式不对直接抛 TokenError。
    """
    if not isinstance(text, str) or len(text) > MAX_TOKEN_CHARS:
        raise TokenError("令牌格式错")
    parts = text.strip().split(".")
    if not parts or parts[0] != expected_prefix:
        raise TokenError("格式不匹配")
    if len(parts) not in (2, 3):
        raise TokenError("格式不匹配")
    if parts_required is not None and len(parts) != parts_required:
        raise TokenError("格式不匹配")

    try:
        payload_raw = crypto.b64d(parts[1])
    except Exception:
        raise TokenError("payload 不是合法 base64")
    if len(payload_raw) > 16384:
        raise TokenError("payload 过大")
    try:
        payload = json.loads(payload_raw.decode())
    except Exception as e:
        raise TokenError(f"payload 不是合法 JSON: {e}")
    if not isinstance(payload, dict):
        raise TokenError("payload 不是对象")

    sig = None
    if len(parts) == 3:
        try:
            sig = crypto.b64d(parts[2])
        except Exception:
            raise TokenError("签名字段不是合法 base64")
        if len(sig) != 64:
            raise TokenError("签名长度不对")
    return payload, payload_raw, sig


def verify_signed_token(text: str, expected_prefix: str, public_key_b64: str) -> dict:
    """解析 + 验签 + 过期检查。返回 payload dict。

    验签失败 / 格式错 / 过期 → 统一抛 TokenError。
    """
    payload, raw, sig = parse_token(text, expected_prefix, parts_required=3)
    try:
        pub = crypto.b64d(public_key_b64)
    except Exception:
        raise TokenError("厂商公钥损坏")
    if not crypto.ed25519_verify(pub, sig, raw):
        raise TokenError("签名无效")
    exp = int(payload.get("exp", 0) or 0)
    if exp and int(time.time()) > exp:
        raise TokenError("已过期")
    return payload


def sign_token(payload: dict, prefix: str, private_key_bytes: bytes) -> str:
    """厂商侧：把 payload 签成完整令牌字符串。"""
    body = crypto.canonical(payload)
    sig = crypto.ed25519_sign(private_key_bytes, body)
    return f"{prefix}.{crypto.b64e(body)}.{crypto.b64e(sig)}"


# ================================================================
# LIC1 卡密（客户端侧）
# ================================================================

def verify_license(text: str, mid: str, machine_enc_priv: bytes,
                   vendor_pub_b64: str, machine_sign_pub_b64: str) -> tuple[dict, bytes]:
    """验一张卡密 → (payload_dict, 解开的内容密钥)。

    五层检查：
      ① Ed25519 验 payload 签名（厂商私钥）
      ② payload 版本必须是 v2
      ③ 过期时间
      ④ 卡密里的 mid / msig 与本机一致
      ⑤ 用本机 X25519 私钥解 ck（换机器/换用户即失败）
    次数限制由调用方自己做（要读 StateStore）。
    """
    payload = verify_signed_token(text, "LIC1", vendor_pub_b64)
    if int(payload.get("v", 0) or 0) != 2:
        raise TokenError("不支持的卡密版本")
    if str(payload.get("mid", "")).lower() != str(mid).lower():
        raise TokenError("机器码不匹配")
    if str(payload.get("msig", "")) != machine_sign_pub_b64:
        raise TokenError("本机密钥不匹配")
    try:
        ck = unwrap_content_key(payload, machine_enc_priv)
    except TokenError:
        raise
    except Exception:
        # AES-GCM InvalidTag：机器公钥不匹配 / ck 被改
        raise TokenError("机器码不匹配")
    return payload, ck


# ================================================================
# ULK1 重置令牌（客户端侧）
# ================================================================

def verify_unlock_token(text: str, public_key_b64: str, mid: str) -> dict:
    """验一张重置令牌 → payload dict。"""
    payload = verify_signed_token(text, "ULK1", public_key_b64)
    if str(payload.get("mid", "")).lower() != str(mid).lower():
        raise TokenError("机器码不匹配")
    if payload.get("mode") not in ("unlock", "attempts", "full"):
        raise TokenError("非法 mode")
    return payload
