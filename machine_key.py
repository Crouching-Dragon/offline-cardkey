"""中层：本机密钥。

首次运行时生成 32 字节随机种子，用 Windows DPAPI 封装后存到
%LOCALAPPDATA%\\OfflineLicGuard\\machine.key —— 只属于当前 Windows 用户 + 本机，
文件复制到别的机器/用户下解不开。

同一个种子派生三样东西：
  * Ed25519 私钥：verifier 给响应签名，app 用卡密里（被厂商签过的）公钥验签
  * X25519 私钥：厂商用它把 content_key 封装进卡密，换机器就解不开
  * 状态 HMAC 密钥：三副本完整性，不再写死在源码里

公开的是两把公钥，私钥永远不出 DPAPI 保护范围（除非攻击者已经能以你的身份运行代码）。
"""
import os
import secrets
import threading

import crypto
import winops

_ENTROPY = b"licguard-machine-v2"
_seed_cache: bytes | None = None
_cache_lock = threading.Lock()


def base_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "OfflineLicGuard")


def key_path() -> str:
    return os.path.join(base_dir(), "machine.key")


def _lock_path() -> str:
    return os.path.join(base_dir(), "machine.lock")


def _unseal(blob: bytes | None) -> bytes | None:
    if not blob:
        return None
    raw = winops.dpapi_unprotect(blob, _ENTROPY)
    return raw if raw and len(raw) == 32 else None


def seed() -> bytes:
    """读取（或首次生成）本机种子。DPAPI 不可用时抛 RuntimeError。"""
    global _seed_cache
    with _cache_lock:
        if _seed_cache is not None:
            return _seed_cache

        current = _unseal(winops.file_read(key_path()))
        if current is not None:
            _seed_cache = current
            return current

        # 首次运行：加锁后再生成，避免 app 和 verifier 各写一份
        os.makedirs(base_dir(), exist_ok=True)
        with winops.file_lock(_lock_path()):
            current = _unseal(winops.file_read(key_path()))
            if current is None:
                current = secrets.token_bytes(32)
                blob = winops.dpapi_protect(current, _ENTROPY)
                if blob is None or not winops.file_write_atomic(key_path(), blob):
                    raise RuntimeError("无法生成本机密钥（DPAPI 不可用或写入失败）")
            _seed_cache = current
            return current


def sign_private() -> bytes:
    return seed()


def sign_public() -> bytes:
    return crypto.ed25519_public_from_private(seed())


def enc_private() -> bytes:
    return crypto.hkdf(seed(), b"licguard-machine-v2", b"x25519")


def enc_public() -> bytes:
    return crypto.x25519_public_from_private(enc_private())


def sign_public_b64() -> str:
    return crypto.b64e(sign_public())


def enc_public_b64() -> str:
    return crypto.b64e(enc_public())


def sign(data: bytes) -> bytes:
    return crypto.ed25519_sign(sign_private(), data)


def state_mac_key() -> bytes:
    return crypto.hkdf(seed(), b"licguard-state-v2", b"state-mac")
