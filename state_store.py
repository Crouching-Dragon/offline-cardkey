"""中层：运行状态三副本存储。

把"往三个地方写同一份状态 → 读出来取 max → 任何副本被改坏就判篡改"
这一整套逻辑封装成类。上层只管 store.load() 和 store.save()。

三副本落点（实测 Windows 上只有 ADS 能被"运行时的 exe"自己写入）：
  ① %LOCALAPPDATA%\\OfflineLicGuard\\state.bin   （普通文件）
  ② HKCU\\Software\\OfflineLicGuard\\s             （注册表，base64）
  ③ <verifier.exe>:licstate                       （NTFS ADS）

HMAC 密钥由本机 DPAPI 保护的机器种子派生（machine_key.state_mac_key），
不再写死在源码里——源码公开也不会让所有人共用一把状态密钥。
"""
import json
import os
import sys

import crypto
import machine_key
import winops


REG_PATH = "OfflineLicGuard"     # 注意：不含 HKCU\Software 前缀，winops.reg_write 自己拼
REG_NAME = "s"
FILE_NAME = "state.bin"
ADS_NAME = "licstate"


def _state_mac_key() -> bytes:
    """状态 HMAC 密钥：由 DPAPI 保护的机器种子派生，每个用户/机器不同。"""
    return machine_key.state_mac_key()


def digest(state: dict, tampered: bool) -> str:
    """状态摘要。重置令牌绑定它，重复使用会因为状态已变而被拒。"""
    body = crypto.canonical(state) + (b"|tampered" if tampered else b"|ok")
    return crypto.sha256_hex(body)


class StateStore:
    """三副本状态存储。"""

    DEFAULT = {
        "lid": "",
        "first": 0, "last": 0, "runtime": 0,
        "runs": 0, "attempts": 0, "lock_until": 0,
    }

    def __init__(self, exe_path: str | None = None):
        """exe_path 传入 verifier.exe 的路径，用来定位 ADS 落点。

        没传时的智能查找顺序：
          1) sys.executable 同目录下的 verifier.exe —— 打包后能找到同目录的 verifier
          2) 如果 verifier.exe 不存在，退回 sys.executable —— 开发态 python.exe 自己
        """
        if exe_path is None:
            sibling = os.path.join(os.path.dirname(sys.executable), "verifier.exe")
            if os.path.exists(sibling):
                exe_path = sibling
            else:
                exe_path = sys.executable
        self.exe_path = exe_path
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        self.file_path = os.path.join(base, "OfflineLicGuard", FILE_NAME)
        self.state_dir = os.path.dirname(self.file_path)

    # ---------------- 序列化 ----------------

    def _pack(self, state: dict) -> bytes:
        body = b"ST2" + crypto.canonical(state)
        return body + crypto.hmac_sha256(_state_mac_key(), body)

    def _unpack(self, blob: bytes) -> dict | None:
        """验证 HMAC 后反序列化。失败返回 None。"""
        if not blob or len(blob) < 64:
            return None
        if blob.startswith(b"ST1"):
            # v2 之前的旧状态：密钥不同，直接丢弃（不当作篡改，避免升级就锁死）
            return None
        if not blob.startswith(b"ST2"):
            return None
        body, mac = blob[:-32], blob[-32:]
        expect = crypto.hmac_sha256(_state_mac_key(), body)
        if not crypto.hmac_equals(mac, expect):
            return None
        try:
            return json.loads(body[3:].decode())
        except Exception:
            return None

    # ---------------- 读 ----------------

    def load(self) -> tuple[dict, bool]:
        """读取状态。返回 (状态字典, 是否检测到篡改)。

        合并规则：三副本逐字段取最大值。这样
          * 改小 runs 绕次数限制 → 取 max 仍是真实次数；
          * 改小 last 绕回拨检测 → 取 max 仍是"最近见过的时间"。
        篡改判定：有副本存在但 HMAC 通不过 → tampered=True。
        """
        blobs: list[bytes] = []
        data = winops.file_read(self.file_path)
        if data is not None:
            blobs.append(data)
        reg = winops.reg_read(REG_PATH, REG_NAME)
        if reg is not None:
            try:
                blobs.append(crypto.b64d(reg))
            except Exception:
                pass
        ads = winops.ads_read(self.exe_path, ADS_NAME)
        if ads is not None:
            blobs.append(ads)

        if not blobs:
            return dict(self.DEFAULT), False

        parsed: list[dict] = []
        tampered = False
        for blob in blobs:
            d = self._unpack(blob)
            if d is None:
                # ST1 是旧版本状态，升级时静默丢弃；其他坏数据才算篡改
                if not blob.startswith(b"ST1"):
                    tampered = True
            else:
                parsed.append(d)

        if not parsed:
            return dict(self.DEFAULT), tampered

        merged = {}
        for field in ("first", "last", "runtime", "runs", "attempts", "lock_until"):
            merged[field] = max(int(d.get(field, 0) or 0) for d in parsed)
        merged["lid"] = parsed[0].get("lid", "")
        return merged, tampered

    # ---------------- 写 ----------------

    def save(self, state: dict) -> None:
        """写三份副本。任何一份失败都静默跳过——多副本就是用来容忍单点故障的。"""
        blob = self._pack(state)
        os.makedirs(self.state_dir, exist_ok=True)
        winops.file_write_atomic(self.file_path, blob)
        winops.reg_write(REG_PATH, REG_NAME, crypto.b64e(blob))
        winops.ads_write(self.exe_path, ADS_NAME, blob)

    # ---------------- 删（reset.py 用） ----------------

    def clear(self) -> None:
        winops.file_delete(self.file_path)
        winops.reg_delete(REG_PATH)
        winops.ads_delete(self.exe_path, ADS_NAME)

    # ---------------- 并发控制 ----------------

    def lock(self):
        """跨进程独占锁：load → 校验 → save 必须包在同一个锁里。"""
        return winops.file_lock(os.path.join(self.state_dir, "state.lock"))
