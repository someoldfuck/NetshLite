import os
import sys
import ctypes
import subprocess
import locale
import hashlib

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def run_as_admin():
    """
    Перезапуск цього ж скрипта з підвищеними правами та коректним робочим каталогом.
    """
    script_path = os.path.abspath(sys.argv[0])
    workdir = os.path.dirname(script_path)
    args = " ".join([f'"{a}"' for a in [script_path] + sys.argv[1:]])
    exe = sys.executable
    h = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args, workdir, 1)
    if int(h) <= 32:
        raise RuntimeError(f"UAC elevation failed, code={h}")
    sys.exit(0)

def sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()

def run_cmd_line(cmd: str):
    enc = locale.getpreferredencoding(False) or "mbcs"
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, shell=True,
            encoding=enc, errors="ignore"
        )
    except Exception as e:
        class R: pass
        r = R(); r.returncode = -1; r.stdout = str(e); r.stderr = str(e)
        return r
