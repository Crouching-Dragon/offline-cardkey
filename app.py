"""高层：app.exe —— 客户端主程序 + authorize() 高层接口。

自己写产品时，只关心 authorize()：

    from licguard.app import authorize

    ok, content = authorize("license.lic")
    if ok:
        run_my_product(content)       # 拿到核心资源明文
    else:
        print(f"授权失败: {content}") # content 是错误码

直接用现成的这个客户端时：
    有卡密 → 验证通过后进入 game.py 的数字炸弹
    没卡密 → 显示激活菜单（生成请求码 / 导入卡密）

authorize() 内部做了三层验证：
  ① 启动前先验 verifier.exe 的厂商签名 → 防被替换成"永远返回 ok"的桩
  ② Popen verifier.exe，stdin 发请求（带 nonce 防重放）
  ③ 用卡密里的本机公钥验响应 Ed25519 签名
  ④ 用 ck 解密 payload.bin → 核心资源明文

任何一步过不去都返回 (False, 错误码)。
"""
import os
import secrets
import sys

import activation
import crypto
import ipc
import lic_token as tk
import runtime
import winops
from vendor_pub import VENDOR_PUBKEY_B64


# 打包后 = exe 所在目录；开发态 = 本文件所在目录
APP_DIR = runtime.program_dir()


def verifier_executable() -> str:
    """定位 verifier。打包后在 dist/ 里和 app.exe 同目录；开发态找 verifier.py。"""
    if runtime.is_compiled():
        return os.path.join(APP_DIR, "verifier.exe")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "verifier.py")


def _check_verifier_authentic(path: str) -> bool:
    """启动前先验 verifier 的 Ed25519 签名，防被替换。"""
    if not runtime.is_compiled():
        return True
    data = winops.file_read(path)
    sig_text = winops.file_read(path + ".sig")
    if data is None or sig_text is None:
        return False
    digest = crypto.sha256_hex(data).encode()
    return crypto.ed25519_verify(
        crypto.b64d(VENDOR_PUBKEY_B64),
        crypto.b64d(sig_text.decode().strip()),
        digest,
    )


def _read_license_payload(lic_path: str) -> dict:
    """读卡密并验厂商签名，返回 payload（含本机公钥 msig）。"""
    try:
        with open(lic_path, "r", encoding="utf-8") as f:
            text = f.read(65536)
    except OSError:
        raise PermissionError("E_LIC_READ")
    return tk.verify_signed_token(text, "LIC1", VENDOR_PUBKEY_B64)


def _ask_verifier(lic_path: str) -> dict:
    """Popen verifier，发请求，用卡密里的机器公钥验响应签名。"""
    payload = _read_license_payload(lic_path)
    sign_pub = str(payload.get("msig", ""))
    if not sign_pub:
        raise PermissionError("E_LIC_FORMAT")

    nonce = secrets.token_bytes(32)
    resp = ipc.run_request(
        verifier_executable(),
        {"v": 2, "nonce": nonce.hex(), "lic": os.path.abspath(lic_path)},
    )
    if not resp.get("ok"):
        raise PermissionError(resp.get("code", "E_UNKNOWN"))

    body = {k: v for k, v in resp.items() if k != "sig"}
    try:
        ok = crypto.ed25519_verify(
            crypto.b64d(sign_pub),
            crypto.b64d(str(resp.get("sig", ""))),
            crypto.canonical(body),
        )
    except Exception:
        ok = False
    if not ok:
        raise PermissionError("E_TAG")
    return resp


def _load_core(ck: bytes) -> str:
    """用 ck 解 payload.bin。没有 ck 就是 InvalidTag，拿不到任何有价值内容。

    打包后 payload.bin 在程序目录；开发态在 temp/ 下。
    """
    data = None
    for p in (os.path.join(APP_DIR, "payload.bin"),
              os.path.join(APP_DIR, "temp", "payload.bin")):
        data = winops.file_read(p)
        if data is not None:
            break
    if data is None:
        raise FileNotFoundError("payload.bin 缺失")
    return crypto.aes_gcm_decrypt(ck, data[12:], data[:12], b"payload-v1").decode("utf-8")


def authorize(lic_path: str) -> tuple[bool, str]:
    """高层接口：一行完成全部授权流程。

    返回 (是否通过, 核心资源明文 | 错误码)
    """
    vp = verifier_executable()
    if not _check_verifier_authentic(vp):
        return False, "E_VERIFIER_INVALID"
    try:
        resp = _ask_verifier(lic_path)
    except (PermissionError, RuntimeError, tk.TokenError) as e:
        return False, str(e)
    except Exception:
        return False, "E_INTERNAL"
    try:
        content = _load_core(crypto.b64d(resp["ck"]))
    except Exception:
        return False, "E_DECRYPT"
    return True, content


# ================================================================
# 命令行入口 —— 演示怎么用 authorize()
# ================================================================

CODE_HINT = {
    "E_LIC_FORMAT": "卡密格式错",
    "E_LIC_READ": "卡密文件不存在或读不到",
    "E_LIC_SIG": "卡密签名无效",
    "E_MACHINE": "卡密与本机不匹配",
    "E_EXPIRED": "卡密已过期",
    "E_RUNS": "次数耗尽",
    "E_CLOCK": "系统时间被回拨",
    "E_TAMPER": "状态被篡改",
    "E_LOCKED": "已被锁定",
    "E_SELF": "verifier 自校验失败",
    "E_VERIFIER_INVALID": "verifier 签名无效",
    "E_TAG": "响应签名校验失败",
    "E_DECRYPT": "核心资源解密失败",
    "E_REQ": "请求格式错",
    "E_MACHINE_KEY": "本机密钥不可用",
    "E_BUSY": "验证进程忙，请稍后重试",
    "E_INTERNAL": "内部错误",
}


def _setup_console() -> None:
    # Windows 控制台默认用 GBK，utf-8 输出会炸 UnicodeEncodeError
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            pass


def _run(lic_path: str) -> int:
    """卡密就绪后：验证 → 通过则进入业务。"""
    ok, result = authorize(lic_path)
    if not ok:
        print(f"[拒绝] {CODE_HINT.get(result, result)}")
        return 1
    print("[通过] 授权有效")
    import game
    game.run(result)
    return 0


def _import_flow() -> bool:
    """让用户粘贴卡密，或者给一个 .lic 文件路径。"""
    print()
    print(" 把厂商发回的卡密粘贴进来（也可以输入 .lic 文件路径）：")
    try:
        text = input(" > ").strip()
    except (EOFError, KeyboardInterrupt):
        return False
    if not text:
        return False
    if not text.startswith("LIC1.") and os.path.isfile(text):
        with open(text, "r", encoding="utf-8") as f:
            text = f.read()

    ok, info = activation.import_license(text)
    if ok:
        print(f"[成功] 激活完成  lid={info}")
        return True
    print(f"[失败] {info}")
    return False


def _activation_menu() -> int:
    """没有卡密时的交互菜单。"""
    while True:
        print()
        print("=" * 52)
        print(" 未激活 —— 本机还没有授权")
        print("=" * 52)
        print(f" 本机机器码：{winops.machine_id()}")
        print("   1) 生成激活请求码（发给厂商）")
        print("   2) 导入厂商发回的卡密")
        print("   0) 退出")
        try:
            choice = input(" 请选择: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 1

        if choice == "1":
            try:
                token = activation.make_request()
            except RuntimeError as e:
                print(f" [失败] {e}")
                continue
            print()
            print(f" 请求码已保存到：{activation.request_path()}")
            print(" 把下面这一整行发给厂商：")
            print("-" * 52)
            print(token)
            print("-" * 52)
        elif choice == "2":
            if _import_flow():
                return _run(activation.license_path())
        elif choice == "0":
            return 1
        else:
            print(" 请输入 0 / 1 / 2")


def main() -> int:
    _setup_console()

    if "--mid" in sys.argv:
        print(winops.machine_id())
        return 0

    # 显式指定卡密文件（调试用）：app.exe <卡密路径>
    bare = [a for a in sys.argv[1:] if not a.startswith("-")]
    if bare:
        return _run(os.path.abspath(bare[0]))

    lic = activation.find_license()
    if lic is None:
        return _activation_menu()
    return _run(lic)


if __name__ == "__main__":
    sys.exit(main())
