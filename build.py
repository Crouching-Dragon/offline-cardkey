"""一条命令打包：python build.py

用 Nuitka 把 Python 编译成 C 再编译成机器码，替代 PyInstaller。
效果：反编译对方拿不到可读源码，破解难度从"几分钟"抬到"几小时"。

流程：
  1. Nuitka 编译 verifier.py → 独立目录
  2. Nuitka 编译 app.py     → 独立目录
  3. 两个目录的依赖合并进 dist/，两个 exe 都放 dist 根目录
  4. 用 vendor.key 给 verifier.exe 签名
  5. 复制 payload.bin

为什么不用 --onefile：
  onefile 运行时会把程序解压到临时目录，sys.executable 指向临时副本。
  这样 verifier 找不到自己的 .sig，ADS 也会写到临时文件上。
  所以用 standalone 目录模式，exe 路径保持真实。
"""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")
BUILD = os.path.join(HERE, "build_nuitka")
TEMP = os.path.join(HERE, "temp")

# 和本框架无关的大包，排除掉能明显缩短编译时间、减小体积
EXCLUDE = ",".join([
    "pygame", "pyglet", "numpy", "matplotlib", "PIL", "scipy",
    "pandas", "tkinter", "unittest", "pydoc", "doctest", "test",
])


def _compile(script: str, name: str) -> str:
    """用 Nuitka 编译成 standalone 目录，返回目录路径。"""
    print(f"[nuitka] 编译 {name} ...（首次运行会自动下载 MinGW，耐心等）", flush=True)

    before = set(os.listdir(BUILD)) if os.path.isdir(BUILD) else set()

    subprocess.check_call([
        sys.executable, "-m", "nuitka",
        "--standalone",
        "--assume-yes-for-downloads",
        # 默认的 depends.exe 解析不了中文路径（Python 装在 D:\python 编程程序），
        # 改用纯 Python 的 pefile 解析 DLL 依赖
        "--experimental=force-dependencies-pefile",
        "--windows-console-mode=force",
        "--output-dir=" + BUILD,
        "--output-filename=" + name + ".exe",
        f"--nofollow-import-to={EXCLUDE}",
        script,
    ], cwd=HERE)

    after = set(os.listdir(BUILD))
    new_dirs = [d for d in (after - before) if d.endswith(".dist")]
    if not new_dirs:
        sys.exit(f"Nuitka 没有产出 .dist 目录，请检查上面的编译日志")

    # 挪到 stage/<name>，这样编译第二个程序时不会互相干扰
    stage = os.path.join(BUILD, "stage", name)
    if os.path.isdir(stage):
        shutil.rmtree(stage)
    shutil.move(os.path.join(BUILD, new_dirs[0]), stage)
    return stage


def _merge_into(src_dir: str, dst_dir: str) -> None:
    """把 src 目录里的文件补齐到 dst（同名文件已存在就跳过）。"""
    for root, _dirs, files in os.walk(src_dir):
        rel = os.path.relpath(root, src_dir)
        target = dst_dir if rel == "." else os.path.join(dst_dir, rel)
        os.makedirs(target, exist_ok=True)
        for fname in files:
            src = os.path.join(root, fname)
            out = os.path.join(target, fname)
            if not os.path.exists(out):
                shutil.copy2(src, out)


def main() -> None:
    if not os.path.exists(os.path.join(TEMP, "vendor.key")):
        sys.exit("请先运行: python keygen.py init")

    # 每次从干净状态开始，避免上次失败的半成品让产物检测出错
    if os.path.isdir(BUILD):
        shutil.rmtree(BUILD)
    os.makedirs(BUILD)

    verifier_stage = _compile("verifier.py", "verifier")
    app_stage = _compile("app.py", "app")

    # 重建 dist/
    if os.path.isdir(DIST):
        shutil.rmtree(DIST)
    os.makedirs(DIST)

    # 两个程序的依赖基本一致，先铺 app 的，再用 verifier 的补齐
    _merge_into(app_stage, DIST)
    _merge_into(verifier_stage, DIST)

    # 两个 exe 必须都在 dist 根目录，app 才能按同目录找到 verifier
    for stage, exe in ((app_stage, "app.exe"), (verifier_stage, "verifier.exe")):
        src = os.path.join(stage, exe)
        if not os.path.exists(src):
            sys.exit(f"缺少 {src}")
        shutil.copy2(src, os.path.join(DIST, exe))

    # verifier.exe 每次重新编译都必须重新签名，否则自校验过不了
    subprocess.check_call([
        sys.executable, "keygen.py", "sign-verifier",
        "--exe", os.path.join(DIST, "verifier.exe"),
    ], cwd=HERE)

    shutil.copy2(os.path.join(TEMP, "payload.bin"),
                 os.path.join(DIST, "payload.bin"))

    # 客户端运行时的临时数据目录（卡密、请求码都放这里，首次运行也会自动创建）
    os.makedirs(os.path.join(DIST, "temp"), exist_ok=True)

    # 默认不带卡密，保持"全新未激活"状态。
    # 调试时加 --with-license 才会把 temp/license.lic 放进去。
    lic = os.path.join(TEMP, "license.lic")
    if "--with-license" in sys.argv and os.path.exists(lic):
        shutil.copy2(lic, os.path.join(DIST, "temp", "license.lic"))

    print("\n完成，产物在 dist/：app.exe  verifier.exe  verifier.exe.sig  payload.bin  temp/")


if __name__ == "__main__":
    main()
