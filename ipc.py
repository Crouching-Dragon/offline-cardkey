"""底层：子进程间通信。

Windows 下 subprocess.Popen 默认会弹控制台黑窗——这个模块把
CREATE_NO_WINDOW flag 永久焊在 Popen 调用里，上层不用再操心。
"""
import json
import subprocess
import sys


# CREATE_NO_WINDOW = 0x08000000，只在 Windows 上有意义；
# Linux/macOS 上 Popen 不认这个参数，所以要条件传。
def _creation_flags():
    if sys.platform == "win32":
        return 0x08000000   # CREATE_NO_WINDOW
    return 0


def run_request(executable: str, request: dict, timeout: int = 15) -> dict:
    """启动一个子进程（verifier.exe），发 JSON 请求，收 JSON 响应。

    请求通过 stdin 管道送进去——不暴露在进程列表里，比命令行参数安全。
    返回子进程 stdout 最后一行解析出的 dict。超时抛 RuntimeError。
    """
    cmd = [executable]
    if executable.endswith(".py"):
        cmd = [sys.executable, executable]

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        creationflags=_creation_flags(),
    )
    payload = json.dumps(request).encode() + b"\n"
    try:
        out, _ = proc.communicate(payload, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise RuntimeError("子进程超时无响应")

    lines = out.decode(errors="replace").strip().splitlines()
    if not lines:
        raise RuntimeError("子进程没有输出")
    if len(out) > 1024 * 1024:
        raise RuntimeError("子进程输出异常")
    # 取最后一行 JSON——前面可能混入 stderr 重定向或引导信息
    data = json.loads(lines[-1])
    if not isinstance(data, dict):
        raise RuntimeError("子进程响应格式错")
    return data


def run_line(executable: str, stdin_text: str = "", timeout: int = 15) -> str:
    """简单版：启动进程，stdin 给一段文本，返回 stdout 全文。"""
    cmd = [executable]
    if executable.endswith(".py"):
        cmd = [sys.executable, executable]

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        creationflags=_creation_flags(),
    )
    out, _ = proc.communicate(stdin_text.encode(), timeout=timeout)
    return out.decode(errors="replace").strip()
