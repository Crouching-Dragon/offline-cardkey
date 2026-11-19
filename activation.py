"""高层：激活流程 —— 首次使用的"生成请求码 / 导入卡密"。

客户第一次运行、手上还没有卡密时走这里：

    make_request()      生成 REQ1 请求码，客户复制后发给厂商
    import_license(x)   导入厂商签发的 LIC1，存到 temp/license.lic

厂商侧对应的命令：
    python keygen.py issue --request REQ1.xxx

所有临时数据都放 temp/：
  开发态   = licguard/temp
  打包安装后 = 安装目录/temp
开源前删掉 temp/ 即可，不会残留卡密。
"""
import os
import secrets
import time

import crypto
import lic_token as tk
import runtime
import winops
from vendor_pub import VENDOR_PUBKEY_B64

TEMP_NAME = "temp"


def temp_dir() -> str:
    """temp 目录路径；不存在时自动创建。"""
    d = os.path.join(runtime.program_dir(), TEMP_NAME)
    os.makedirs(d, exist_ok=True)
    return d


def license_path() -> str:
    """本机卡密文件的固定位置。"""
    return os.path.join(temp_dir(), "license.lic")


def request_path() -> str:
    """生成的请求码保存位置。"""
    return os.path.join(temp_dir(), "request.txt")


def find_license(explicit: str | None = None) -> str | None:
    """按优先级找卡密文件：显式路径 → temp/license.lic → 程序目录/license.lic。"""
    candidates = (
        explicit,
        license_path(),
        os.path.join(runtime.program_dir(), "license.lic"),
    )
    for p in candidates:
        if p and os.path.isfile(p):
            return p
    return None


def make_request(mode: str = "activate") -> str:
    """生成激活请求码，写入 temp/request.txt，同时返回字符串。"""
    payload = {
        "v": 1,
        "mid": winops.machine_id(),
        "mode": mode,
        "ts": int(time.time()),
        "nonce": secrets.token_hex(16),
    }
    token = "REQ1." + crypto.b64e(crypto.canonical(payload))
    winops.file_write(request_path(), token.encode("utf-8"))
    return token


def import_license(text: str) -> tuple[bool, str]:
    """导入卡密文本。

    会先完整验一遍（签名 + 过期 + 机器绑定），通过了才落盘，
    避免存进去一张用不了的卡密。
    返回 (是否成功, lid | 失败原因)。
    """
    text = (text or "").strip()
    if not text:
        return False, "卡密内容为空"

    mid = winops.machine_id()
    try:
        payload, _ck = tk.verify_license(text, mid, VENDOR_PUBKEY_B64)
    except tk.TokenError as e:
        return False, str(e)
    except Exception:
        # verify_license 里 ck 解不开时抛的是 AES-GCM 的 InvalidTag
        return False, "卡密与本机不匹配（或内容已损坏）"

    if not winops.file_write(license_path(), text.encode("utf-8")):
        return False, "写入 temp/license.lic 失败"
    return True, payload.get("lid", "")
