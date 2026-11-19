"""底层：运行环境判断。

PyInstaller 和 Nuitka 判断"是否打包运行"的方式不一样：
  * PyInstaller 会设置 sys.frozen = True
  * Nuitka 会在每个被编译的模块里注入 __compiled__ 变量

所以这里统一封装成一个函数，上层不要自己写 getattr(sys, "frozen", ...)。
"""
import os
import sys

import winops


def is_compiled() -> bool:
    """当前是否运行在打包后的 exe 里（Nuitka 或 PyInstaller 都返回 True）。

    开发态直接 python xxx.py 运行时返回 False。
    """
    return "__compiled__" in globals() or getattr(sys, "frozen", False)


def program_dir() -> str:
    """程序所在目录。

    打包后 = exe 自己所在的目录（用 Win32 API 取，不依赖 sys.executable）；
    开发态 = 源码文件所在目录。
    """
    if is_compiled():
        return os.path.dirname(os.path.abspath(winops.current_exe()))
    return os.path.dirname(os.path.abspath(__file__))
