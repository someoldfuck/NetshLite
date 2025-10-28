import os
import re
import json
from datetime import datetime

from .utils import sha1, run_cmd_line
from .pshell import run_powershell
from .db import save_db

# ---------- Правила Firewall ----------
def add_rule(program_path: str):
    prog = program_path.replace("/", "\\")
    h = sha1(program_path)
    in_name  = f"Block_{h}"
    out_name = f"Block_{h}_out"
    r1 = run_cmd_line(
        f'netsh advfirewall firewall add rule name="{in_name}" '
        f'program="{prog}" action=block dir=in enable=yes profile=any'
    )
    r2 = run_cmd_line(
        f'netsh advfirewall firewall add rule name="{out_name}" '
        f'program="{prog}" action=block dir=out enable=yes profile=any'
    )
    return r1, r2

def delete_rule_by_path(program_path: str):
    h = sha1(program_path)
    in_name  = f"Block_{h}"
    out_name = f"Block_{h}_out"
    r1 = run_cmd_line(f'netsh advfirewall firewall delete rule name="{in_name}"')
    r2 = run_cmd_line(f'netsh advfirewall firewall delete rule name="{out_name}"')
    return r1, r2

def update_rule(program_path: str):
    """
    Видаляє обидва правила (in/out) і знову додає їх.
    Повертає: ((d1, d2), (a1, a2)) — дві пари CompletedProcess.
    """
    d1, d2 = delete_rule_by_path(program_path)
    a1, a2 = add_rule(program_path)
    return (d1, d2), (a1, a2)

# ---------- Високорівнево з БД ----------
def block_program(db: dict, path: str, note: str = ""):
    if not os.path.isfile(path):
        raise FileNotFoundError("Файл не знайдено")
    r1, r2 = add_rule(path)
    h = sha1(path)
    db[h] = {"path": path, "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "note": note}
    save_db(db)
    return r1, r2

def unblock_program(db: dict, path: str):
    r1, r2 = delete_rule_by_path(path)
    h = sha1(path)
    if h in db:
        del db[h]
        save_db(db)
    return r1, r2

# ---------- Відновлення зі справжніх правил ----------
_PATH_RE = re.compile(r'(?:"?([A-Za-z]:\\[^"\r\n]*?\.exe)"?)|(?:"?(\\\\[^"\r\n]*?\.exe)"?)')

def _get_rules_from_powershell():
    ps = (
        "try {"
        "  $rules = Get-NetFirewallRule -PolicyStore ActiveStore -DisplayName 'Block_*' -ErrorAction SilentlyContinue;"
        "  if ($null -eq $rules) { '' | Out-String; exit 0 }"
        "  $apps = $rules | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | "
        "          Select-Object -ExpandProperty Program;"
        "  $apps | ForEach-Object { $_ }"
        "} catch { '' }"
    )
    res = run_powershell(ps)
    if res.returncode != 0 or not res.stdout:
        return []
    paths = [ln.strip().strip('"') for ln in res.stdout.splitlines() if ln.strip()]
    uniq, seen = [], set()
    for p in paths:
        if p and p not in seen:
            seen.add(p); uniq.append(p)
    return uniq

def _get_rules_from_netsh_fallback():
    res = run_cmd_line("netsh advfirewall firewall show rule name=all")
    if res.returncode != 0 or not res.stdout:
        return []

    lines = res.stdout.splitlines()

    rule_name_keys = (
        "rule name", "имя правила", "название правила",
        "назва правила", "ім’я правила", "імя правила"
    )
    program_keys = (
        "program", "программа", "програма",
        "шлях до програми", "путь к программе",
        "application", "app"
    )

    def _is_key_line(s: str, keys) -> bool:
        s = s.strip().lower()
        if ":" not in s:
            return False
        key = s.split(":", 1)[0].strip()
        return any(key.startswith(k) for k in keys)

    def _after_colon(s: str) -> str:
        return s.split(":", 1)[1].strip() if ":" in s else ""

    paths = []
    keep = False

    for raw in lines:
        line = raw.strip()
        if not line:
            continue

        if _is_key_line(line, rule_name_keys):
            name = _after_colon(line)
            keep = name.startswith("Block_")
            continue

        if keep and _is_key_line(line, program_keys):
            prog = _after_colon(line)
            if prog and prog.lower() != "any":
                paths.append(prog.strip('"'))
            keep = False
            continue

        if keep:
            m = _PATH_RE.search(line)
            if m:
                candidate = m.group(1) or m.group(2)
                if candidate:
                    paths.append(candidate)
                    keep = False

    if not paths:
        lookahead = 12
        n = len(lines)
        for i, raw in enumerate(lines):
            line = raw.strip()
            if "Block_" in line:
                for j in range(i, min(i + lookahead, n)):
                    m = _PATH_RE.search(lines[j])
                    if m:
                        candidate = (m.group(1) or m.group(2))
                        if candidate:
                            paths.append(candidate)
                            break

    uniq, seen = [], set()
    for p in paths:
        if p:
            p = p.strip().strip('"')
            if p not in seen:
                seen.add(p); uniq.append(p)
    return uniq

def get_rules_from_firewall():
    paths = _get_rules_from_powershell()
    if paths:
        return paths
    return _get_rules_from_netsh_fallback()

def rebuild_db_from_firewall(db: dict, note_mark="(відновлено)"):
    found = get_rules_from_firewall()
    added = 0
    for p in found:
        h = sha1(p)
        if h not in db:
            db[h] = {
                "path": p,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "note": note_mark
            }
            added += 1
    if added:
        save_db(db)
    return added, len(found)

# ---------- Нове: список запущених процесів ----------
def list_running_processes():
    """
    Повертає список dict: {'pid': int, 'name': str, 'path': str}
    Використовує CIM (мовонезалежно), без сторонніх бібліотек.
    """
    ps = (
        "try {"
        "  $procs = Get-CimInstance Win32_Process | "
        "           Select-Object ProcessId, Name, ExecutablePath | "
        "           Where-Object { $_.ExecutablePath } | "
        "           ConvertTo-Json -Depth 3 -Compress;"
        "  $procs;"
        "} catch { '[]' }"
    )
    res = run_powershell(ps)
    if res.returncode != 0 or not res.stdout:
        return []
    try:
        data = json.loads(res.stdout)
        if isinstance(data, dict):
            data = [data]
    except Exception:
        return []
    out = []
    for it in data:
        pid = it.get("ProcessId")
        name = it.get("Name") or ""
        path = it.get("ExecutablePath") or ""
        if path:
            out.append({"pid": int(pid) if pid is not None else -1,
                        "name": str(name),
                        "path": str(path)})
    # унікалізуємо за (pid,path) та сортуємо за name
    seen = set()
    uniq = []
    for d in out:
        key = (d["pid"], d["path"].lower())
        if key not in seen:
            seen.add(key)
            uniq.append(d)
    uniq.sort(key=lambda d: (d["name"].lower(), d["path"].lower()))
    return uniq
