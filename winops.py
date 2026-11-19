"""底层：Windows 系统操作。

把注册表、NTFS ADS、机器码获取这些"难写的 Windows 专属脏活"全封装起来。
上层代码只调函数，不碰 winreg / ctypes / CreateFileW 这些。

实测事实（重要）：
  运行中的 exe 主文件被系统映像锁定，追加写入会报 ERROR_SHARING_VIOLATION (32)。
  但 NTFS ADS（备用数据流）可以写，所以状态记录存在 ADS 里作为第三副本。
"""
import ctypes
import os
import sys
from ctypes import wintypes

import crypto  # 只用 sha256_hex，底层模块之间无循环依赖

try:
    import winreg
except ImportError:  # Linux/macOS 上没 winreg
    winreg = None


# ================================================================
# 当前进程的 exe 路径
# ================================================================

def current_exe() -> str:
    """当前进程对应的 exe 完整路径。

    为什么不直接用 sys.executable：不同打包器对它的设置不一样
    （PyInstaller 指向自身，Nuitka 的行为又不同），拿它算 SHA-256
    会读到错误的文件。Win32 的 GetModuleFileNameW 永远返回真实路径。
    """
    if sys.platform == "win32":
        buf = ctypes.create_unicode_buffer(32768)
        n = ctypes.windll.kernel32.GetModuleFileNameW(None, buf, 32768)
        if n:
            return buf.value
    return sys.executable


# ================================================================
# 机器码
# ================================================================

def _volume_serial(root: str = "C:\\") -> str:
    """系统盘卷序列号。格式化时生成，重装系统盘后变。"""
    serial = wintypes.DWORD(0)
    ok = ctypes.windll.kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(root), None, 0,
        ctypes.byref(serial), None, None, None, 0,
    )
    return f"{serial.value:08X}" if ok else "NOSERIAL"


def _machine_guid() -> str:
    """Windows 安装时生成的 MachineGuid。重装系统会变。"""
    if winreg is None:
        return "NOGUID"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Cryptography") as k:
            return winreg.QueryValueEx(k, "MachineGuid")[0]
    except OSError:
        return "NOGUID"


def machine_id() -> str:
    """64 位十六进制的机器指纹。

    算法: sha256("mid-v1|<卷序列号>|<MachineGuid>")
    组合两个因子是为了防伪造：单独用卷序列号可被 diskgenius 类工具伪造；
    单独用 MachineGuid 可被注册表恢复；两个一起改成本就高了。
    """
    raw = f"mid-v1|{_volume_serial()}|{_machine_guid()}"
    return crypto.sha256_hex(raw.encode())


# ================================================================
# 注册表读写（HKCU\Software\<path>）
# ================================================================

def reg_write(path: str, name: str, value: str) -> bool:
    """写注册表值。path 不需要带 HKCU\\Software 前缀，自己拼。"""
    if winreg is None:
        return False
    key_path = fr"Software\{path}"
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)
        return True
    except OSError:
        return False


def reg_read(path: str, name: str) -> str | None:
    """读注册表值。不存在或权限不足返回 None。"""
    if winreg is None:
        return None
    key_path = fr"Software\{path}"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def reg_delete(path: str, name: str | None = None) -> bool:
    """删除注册表值；name=None 时删除整个子键。"""
    if winreg is None:
        return False
    key_path = fr"Software\{path}"
    try:
        if name is None:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
        else:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0,
                                winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, name)
        return True
    except OSError:
        return False


# ================================================================
# NTFS ADS（备用数据流）
# 实测运行中的 exe 主文件不能写，但它的 ADS 可以写。
# ================================================================

def ads_write(file_path: str, stream_name: str, data: bytes) -> bool:
    """往 <file>:<stream_name> 写数据。"""
    try:
        with open(f"{file_path}:{stream_name}", "wb") as f:
            f.write(data)
        return True
    except OSError:
        return False


def ads_read(file_path: str, stream_name: str) -> bytes | None:
    """读 <file>:<stream_name>。不存在返回 None。"""
    try:
        with open(f"{file_path}:{stream_name}", "rb") as f:
            return f.read()
    except OSError:
        return None


def ads_delete(file_path: str, stream_name: str) -> bool:
    """删除 <file>:<stream_name>。

    某些 Python/PyInstaller 打包的 exe 上 os.remove + DeleteFileW 都会"假成功"——
    调用返回 True 但流实际还在。此时用覆盖兜底：写一小段垃圾数据让 HMAC 失效，
    上层 load() 会返回 tampered=True，自然触发重置。
    """
    target = f"{file_path}:{stream_name}"
    try:
        os.remove(target)
    except OSError:
        pass

    # 删掉了就好；删不掉（流还能读）就覆盖
    try:
        f = open(target, "rb")
        leftover = f.read()
        f.close()
        if leftover:
            # 覆盖成非法 blob → load() 会判定 tampered
            f = open(target, "wb")
            f.write(b"\x00" * 32)
            f.close()
        return True
    except OSError:
        return True


# ================================================================
# 普通文件读写
# ================================================================

def file_write(path: str, data: bytes) -> bool:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        return True
    except OSError:
        return False


def file_read(path: str) -> bytes | None:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def file_delete(path: str) -> bool:
    try:
        os.remove(path)
        return True
    except OSError:
        return False
