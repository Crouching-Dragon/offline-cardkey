"""底层：加解密工具。

只管纯密码学原语的封装。不涉及任何业务概念（没有"卡密"、"状态"、"机器码"）。
其他任何模块要做加解密，直接 import 这里。
"""
import base64
import hashlib
import hmac
import json

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ================================================================
# Base64
# ================================================================

def b64e(data: bytes) -> str:
    """URL-safe Base64 编码，去掉末尾 '=' 填充。"""
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64d(text: str) -> bytes:
    """URL-safe Base64 解码，自动补回 '=' 填充。"""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ================================================================
# 稳定 JSON 序列化（签名/验签时两边必须逐字节一致）
# ================================================================

def canonical(obj) -> bytes:
    """把 Python 对象序列化成稳定的 JSON 字节串。

    稳定 = key 排序、无额外空格、UTF-8。签名前必调。
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


# ================================================================
# HKDF（RFC 5869）
# ================================================================

def hkdf(key: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 密钥派生。把一个密钥派生成多个不同用途的子密钥。"""
    prk = hmac.new(salt or b"\x00" * 32, key, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA256。"""
    return hmac.new(key, message, hashlib.sha256).digest()


def hmac_equals(a: bytes, b: bytes) -> bool:
    """常量时间比较，防时序侧信道。"""
    return hmac.compare_digest(a, b)


# ================================================================
# AES-GCM（带认证的对称加密）
# ================================================================

def aes_gcm_encrypt(key: bytes, plaintext: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
    """AES-GCM 加密。返回密文（含认证标签，无需单独处理）。"""
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_gcm_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
    """AES-GCM 解密。密钥/nonce/aad/密文任一项不匹配都会抛 InvalidTag。"""
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


# ================================================================
# Ed25519 签名（非对称）
# ================================================================

def ed25519_sign(private_key_bytes: bytes, message: bytes) -> bytes:
    """Ed25519 签名。"""
    pk = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return pk.sign(message)


def ed25519_verify(public_key_bytes: bytes, signature: bytes, message: bytes) -> bool:
    """Ed25519 验签。返回 True/False，不抛异常。"""
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, message)
        return True
    except InvalidSignature:
        return False


def ed25519_keygen() -> tuple[bytes, bytes]:
    """生成一对 Ed25519 (私钥32字节, 公钥32字节)。"""
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


def sha256(data: bytes) -> bytes:
    """SHA-256 哈希（返回 32 字节）。"""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """SHA-256 哈希（返回 64 位十六进制字符串）。"""
    return hashlib.sha256(data).hexdigest()
