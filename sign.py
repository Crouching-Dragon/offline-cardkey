"""厂商侧：交互式卡密签发工具。

keygen.py 是命令行；这个程序只负责"把参数问出来"，
真正的签发仍然调用 keygen.py issue，不重复实现任何签名逻辑。

跑法：
    python sign.py

功能覆盖：
    粘贴请求码 / 从文件选请求码 / 直接输入机器码
    有效期、次数、输出位置
    更换私钥文件（默认 temp/vendor.key）
    签发后自动复制卡密到剪贴板
"""
import os
import subprocess
import sys

import lic_token as ltoken

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_KEY = os.path.join(HERE, "temp", "vendor.key")
DEFAULT_OUT = os.path.join(HERE, "temp", "license.lic")


def _setup_console() -> None:
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stdin.reconfigure(encoding="utf-8")
        except Exception:
            pass


def _ask(prompt: str, default: str = "") -> str:
    """读一行；直接回车就用默认值。"""
    try:
        raw = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return raw if raw else default


def _pick_file(title: str) -> str | None:
    """弹 Windows 文件选择框；环境不支持时返回 None。"""
    try:
        import tkinter
        from tkinter import filedialog

        root = tkinter.Tk()
        root.withdraw()
        path = filedialog.askopenfilename(title=title)
        root.destroy()
        return path or None
    except Exception:
        return None


def _parse_request(text: str) -> dict | None:
    """从 REQ1 里取出机器码和两把公钥，格式不对返回 None。"""
    try:
        payload, _, _ = ltoken.parse_token((text or "").strip(), "REQ1", parts_required=2)
        return {
            "mid": str(payload.get("mid", "")).lower(),
            "msig": str(payload.get("msig", "")),
            "menc": str(payload.get("menc", "")),
        }
    except Exception:
        return None


def _copy_to_clipboard(text: str) -> bool:
    """卡密是纯 ASCII，用 clip 直接塞进剪贴板。"""
    try:
        p = subprocess.Popen("clip", stdin=subprocess.PIPE, shell=True)
        p.communicate(text.encode("utf-8"))
        return p.returncode == 0
    except Exception:
        return False


def _issue_flow(info: dict, key_path: str) -> None:
    print()
    print(f" 已识别机器码：{info['mid']}")
    print(f" 机器公钥：msig={info['msig'][:12]}…  menc={info['menc'][:12]}…")
    days = _ask(" 有效期天数（0=永久，默认 365）: ", "365")
    runs = _ask(" 启动次数（0=不限，默认 0）: ", "0")
    out = _ask(f" 输出文件（默认 temp{os.sep}license.lic，回车即可）: ", DEFAULT_OUT)

    try:
        int(days), int(runs)
    except ValueError:
        print(" [失败] 天数 / 次数必须是整数")
        return

    cmd = [
        sys.executable, os.path.join(HERE, "keygen.py"), "issue",
        "--mid", info["mid"],
        "--msig", info["msig"],
        "--menc", info["menc"],
        "--days", days, "--runs", runs, "--out", out,
    ]
    if os.path.abspath(key_path) != os.path.abspath(DEFAULT_KEY):
        cmd += ["--key", key_path]

    r = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        print(" [失败]", (r.stderr or r.stdout or "").strip())
        input(" 按回车返回菜单...")
        return

    print()
    print(" [成功]", (r.stdout or "").strip())

    try:
        with open(out, encoding="utf-8") as f:
            lic = f.read().strip()
    except OSError as e:
        print(f" [警告] 卡密已写入，但读取失败: {e}")
        input(" 按回车返回菜单...")
        return

    print()
    print(" 把下面这一整行发给客户：")
    print("-" * 64)
    print(lic)
    print("-" * 64)
    if _copy_to_clipboard(lic):
        print(" （已自动复制到剪贴板）")

    input(" 按回车返回菜单...")


def main() -> int:
    _setup_console()
    key_path = DEFAULT_KEY

    while True:
        print()
        print("=" * 64)
        print("  卡密签发工具")
        print("=" * 64)
        mark = "✓ 已找到" if os.path.isfile(key_path) else "✗ 不存在"
        print(f"  当前私钥：{key_path}")
        print(f"            {mark}")
        print()
        print("   1) 粘贴客户请求码（REQ1...）")
        print("   2) 从文件选择请求码")
        print("   3) 直接输入机器码")
        print("   4) 更换私钥文件")
        print("   0) 退出")

        try:
            choice = input(" 请选择: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if choice == "0":
            return 0

        if choice in ("1", "2", "3") and not os.path.isfile(key_path):
            print(" [错误] 私钥不存在。先跑 keygen.py init，或选 4 指定私钥文件")
            continue

        if choice == "1":
            print()
            text = _ask(" 粘贴请求码: ")
            info = _parse_request(text)
            if info is None:
                print(" [错误] 请求码格式不对，应该以 REQ1. 开头")
                continue
            _issue_flow(info, key_path)

        elif choice == "2":
            path = _pick_file("选择请求码文件") or ""
            if not path:
                path = _ask(" 输入请求码文件路径: ")
            if not path:
                continue
            try:
                with open(path, encoding="utf-8") as f:
                    text = f.read()
            except OSError as e:
                print(f" [错误] 读取失败: {e}")
                continue
            info = _parse_request(text)
            if info is None:
                print(" [错误] 文件里不是合法的 REQ1 请求码")
                continue
            _issue_flow(info, key_path)

        elif choice == "3":
            print()
            mid = _ask(" 输入机器码（64 位十六进制）: ").lower()
            if len(mid) != 64 or any(c not in "0123456789abcdef" for c in mid):
                print(" [错误] 机器码应该是 64 位十六进制")
                continue
            msig = _ask(" 输入客户 Ed25519 公钥 msig（base64）: ").strip()
            menc = _ask(" 输入客户 X25519 公钥 menc（base64）: ").strip()
            _issue_flow({"mid": mid, "msig": msig, "menc": menc}, key_path)

        elif choice == "4":
            print()
            path = _pick_file("选择私钥文件") or ""
            if not path:
                path = _ask(" 输入私钥文件路径: ")
            if not path:
                continue
            if os.path.isfile(path):
                key_path = os.path.abspath(path)
                print(f" [OK] 私钥已切换：{key_path}")
            else:
                print(" [错误] 文件不存在")

        else:
            print(" 请输入 0 / 1 / 2 / 3 / 4")


if __name__ == "__main__":
    sys.exit(main())
