import subprocess
import locale

def run_powershell(ps_script: str):
    """
    Запустити PowerShell у no-profile/non-interactive режимі.
    """
    enc = locale.getpreferredencoding(False) or "mbcs"
    cmd = (
        'powershell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass '
        f'-Command "{ps_script}"'
    )
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, shell=True,
            encoding=enc, errors="ignore"
        )
    except Exception as e:
        class R: pass
        r = R(); r.returncode = -1; r.stdout = str(e); r.stderr = str(e)
        return r
