"""中层：卡密 + 重置令牌 + 机器码绑定。

统一处理三种令牌格式：
  LIC1.<payload_b64>.<sig_b64>   —— 签发的卡密（Ed25519 签）
  ULK1.<payload_b64>.<sig_b64>   —— 签发的重置令牌（Ed25519 签）
  REQ1.<payload_b64>             —— 客户发给厂商的请求码（无签名）

机器码派生 wrap_key 的逻辑也在这里统一放，keygen 和 verifier/app 都调用同一个函数。
"""
import json
import secrets
import time

import crypto
import winops


# ================================================================
# 机器码绑定 —— 派生 wrap_key
# ================================================================

def wrap_key_for(machine_id_hex: str) -> bytes:
    """由机器码派生包裹密钥。

    keygen 在签发卡密时用它把内容密钥 AES-GCM 加密塞进 ck 字段；
    verifier 在验证时用它解包 ck；
    换机器 → HKDF 输出不同 → AES-GCM 认证标签不匹配 → ck 解不开。
    """
    return crypto.hkdf(bytes.fromhex(machine_id_hex), b"lic-wrap-v1", b"content-key")


def wrap_content_key(content_key: bytes, machine_id_hex: str) -> str:
    """厂商侧：把内容密钥包装成可塞进卡密的 b64 字符串。"""
    nonce = secrets.token_bytes(12)
    ct = crypto.aes_gcm_encrypt(wrap_key_for(machine_id_hex), content_key, nonce, b"ck-wrap")
    return crypto.b64e(nonce + ct)


def unwrap_content_key(ck_b64: str, machine_id_hex: str) -> bytes:
    """客户端侧：解开卡密里的内容密钥。

    失败原因（都是 AES-GCM InvalidTag）：
      * 机器码不匹配（最常见）
      * ck 字段被篡改
      * aad 不匹配
    """
    blob = crypto.b64d(ck_b64)
    nonce, ct = blob[:12], blob[12:]
    return crypto.aes_gcm_decrypt(wrap_key_for(machine_id_hex), ct, nonce, b"ck-wrap")


# ================================================================
# 统一的令牌解析
# 三种格式都是 "<前缀>.<payload_b64>[.<sig_b64>]"，结构一致。
# ================================================================

class TokenError(Exception):
    """令牌解析/验签失败时抛的统一异常。"""
    pass


def parse_token(text: str, expected_prefix: str) -> tuple[dict, bytes, bytes | None]:
    """拆分令牌 → (payload_dict, payload_raw_bytes, signature_or_None)。

    REQ1 只有两段，返回 (payload, raw, None)；
    LIC1 / ULK1 三段都有，返回 (payload, raw, sig_bytes)。
    格式不对直接抛 TokenError。
    """
    parts = text.strip().split(".")
    if not parts or parts[0] != expected_prefix:
        raise TokenError("格式不匹配")

    payload_raw = crypto.b64d(parts[1])
    try:
        payload = json.loads(payload_raw.decode())
    except Exception as e:
        raise TokenError(f"payload 不是合法 JSON: {e}")

    sig = None
    if len(parts) >= 3:
        try:
            sig = crypto.b64d(parts[2])
        except Exception:
            raise TokenError("签名字段不是合法 base64")
    return payload, payload_raw, sig


def verify_signed_token(text: str, expected_prefix: str, public_key_b64: str) -> dict:
    """解析 + 验签 + 可选过期检查。返回 payload dict。

    验签失败 / 格式错 / 过期 → 统一抛 TokenError。
    """
    payload, raw, sig = parse_token(text, expected_prefix)
    if sig is None:
        raise TokenError("缺少签名字段")
    pub = crypto.b64d(public_key_b64)
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

def verify_license(text: str, mid: str, public_key_b64: str) -> tuple[dict, bytes]:
    """验一张卡密 → (payload_dict, 解开的内容密钥)。

    四层检查：
      ① Ed25519 验 payload 签名
      ② 过期时间
      ③ 机器码绑定（解 ck，失败即机器不匹配）
    次数限制由调用方自己做（要读 StateStore）。
    """
    payload = verify_signed_token(text, "LIC1", public_key_b64)
    exp = int(payload.get("exp", 0) or 0)
    if exp and int(time.time()) > exp:
        raise TokenError("E_EXPIRED")
    ck = unwrap_content_key(payload["ck"], mid)
    return payload, ck


# ================================================================
# ULK1 重置令牌（客户端侧）
# ================================================================

def verify_unlock_token(text: str, public_key_b64: str, mid: str) -> dict:
    """验一张重置令牌 → payload dict。"""
    payload = verify_signed_token(text, "ULK1", public_key_b64)
    if payload.get("mid") != mid:
        raise TokenError("机器码不匹配")
    if payload.get("mode") not in ("unlock", "attempts", "full"):
        raise TokenError("非法 mode")
    return payload
