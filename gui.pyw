# -*- coding: utf-8 -*-
# Firewall Manager — with rule-search upgrades: export, hotkeys, presets, mass reinstall, autosync DB
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import os, sys, subprocess, shutil, json
from datetime import datetime

from firewall_manager.utils import is_admin, run_as_admin
from firewall_manager.db import load_db, save_db, clear_db, backup_db, import_db
from firewall_manager.allowdb import load_allow_db
from firewall_manager.core import (
    block_program, unblock_program, update_rule,
    rebuild_db_from_firewall, list_running_processes, delete_rule_by_path,
    allow_program
)
from firewall_manager.ui_helpers import install_shortcuts, append_log, clear_log as ui_clear_log
from firewall_manager.monitor import OutboundConnectionMonitor
from firewall_manager.tray import TrayController

# ---- working dir ----
SCRIPT_PATH = os.path.abspath(sys.argv[0])
SCRIPT_DIR  = os.path.dirname(SCRIPT_PATH)
try:
    os.chdir(SCRIPT_DIR)
except Exception:
    pass

# ---- admin check ----
if not is_admin():
    try:
        run_as_admin()
    except Exception as e:
        _tmp = tk.Tk(); _tmp.withdraw()
        messagebox.showerror("Помилка UAC", f"Не вдалося отримати адмін-права:\n{e}")
        _tmp.destroy()
        sys.exit(1)

# ---- DB ----
db = load_db()
allow_db = load_allow_db()

# ---- background controllers ----
connection_monitor = None
tray_controller = None

# ---- helpers: netsh & encoding-safe runner ----
def _netsh_path():
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    candidates = [
        os.path.join(sysroot, "System32", "netsh.exe"),
        os.path.join(sysroot, "Sysnative", "netsh.exe"),
        shutil.which("netsh"),
        "netsh",
    ]
    for c in candidates:
        if c and isinstance(c, str) and os.path.exists(c):
            return c
    return "netsh"

def _run(cmd):
    try:
        if isinstance(cmd, (str, bytes)):
            cmd = [cmd]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False)
        data = proc.communicate()[0] or b""
        rc = proc.returncode
        text = None
        for enc in ("utf-8", "utf-16le", "utf-16", "cp1251", "cp866", "mbcs"):
            try:
                text = data.decode(enc)
                break
            except Exception:
                continue
        if text is None:
            text = data.decode("latin-1", errors="replace")
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        return rc == 0, text
    except FileNotFoundError as e:
        return False, f"Не знайдено виконуваний файл: {e}"
    except Exception as e:
        return False, str(e)

def _list_rules(dir_filter=None):
    args = [_netsh_path(), "advfirewall", "firewall", "show", "rule", "name=all"]
    if dir_filter in ("in","out"):
        args.append(f"dir={dir_filter}")
    ok, out = _run(args)
    if not ok:
        raise RuntimeError(out)

    def canon_key(k):
        lk = k.strip().lower()
        if lk.startswith("rule name") or "назва правил" in lk or "назва правила" in lk or "имя правила" in lk:
            return "Rule Name"
        if "direction" in lk or "напрям" in lk or "направлен" in lk:
            return "Direction"
        if "action" in lk or "дія" in lk or "действ" in lk:
            return "Action"
        if "enabled" in lk or "увімк" in lk or "включ" in lk:
            return "Enabled"
        if "program" in lk or "програма" in lk or "программа" in lk:
            return "Program"
        return k.strip()

    rules = []
    current = {}
    for line in out.split("\n"):
        s = line.strip()
        if not s:
            if current.get("Rule Name"):
                rules.append(current); current = {}
            continue
        if set(s) <= {"-","—"," "}:
            continue
        if ":" in s:
            k,v = s.split(":",1)
            ck = canon_key(k); cv = v.strip()
            if ck == "Rule Name" and current.get("Rule Name"):
                rules.append(current); current = {}
            current[ck] = cv
            continue
        if not current.get("Rule Name") and len(s) > 0:
            current["Rule Name"] = s
    if current.get("Rule Name"):
        rules.append(current)
    return rules

def _delete_rule_precise(rule):
    name = rule.get("Rule Name") or rule.get("Name") or ""
    direction = (rule.get("Direction") or "").lower()
    program = rule.get("Program") or ""
    cmd = [_netsh_path(), "advfirewall", "firewall", "delete", "rule", f'name={name}']
    if direction in ("in","out"):
        cmd.append(f"dir={direction}")
    if program:
        cmd.append(f'program={program}')
    ok, out = _run(cmd)
    return ok, out

# ---- presets (quick exe buttons) ----
PRESETS_FILE = os.path.join(SCRIPT_DIR, "presets.json")
def load_presets():
    if os.path.exists(PRESETS_FILE):
        try:
            with open(PRESETS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_presets(presets):
    try:
        with open(PRESETS_FILE, "w", encoding="utf-8") as f:
            json.dump(presets, f, ensure_ascii=False, indent=2)
    except Exception as e:
        append_log(log_text, f"Помилка збереження пресетів: {e}")

presets = load_presets()

def add_preset(name, path):
    global presets
    presets.append({"name": name, "path": path})
    save_presets(presets)
    rebuild_presets_ui()

def remove_preset(index):
    global presets
    try:
        presets.pop(index)
        save_presets(presets)
        rebuild_presets_ui()
    except Exception:
        pass

# ---- UI helpers ----
def clear_log():
    ui_clear_log(log_text, status_var)

def select_file():
    fp = filedialog.askopenfilename(title="Обрати програму", filetypes=[("EXE","*.exe"),("All","*.*")])
    if fp:
        entry_path.delete(0, tk.END); entry_path.insert(0, fp)

def save_log_to_file():
    default_name = f"firewall_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    path = filedialog.asksaveasfilename(title="Зберегти лог у файл", defaultextension=".txt", initialfile=default_name,
                                        filetypes=[("Текстовий файл","*.txt"),("Усі файли","*.*")])
    if not path: return
    try:
        data = log_text.get("1.0","end-1c")
        with open(path,"w",encoding="utf-8") as f: f.write(data)
        append_log(log_text, f"🧾 Лог збережено: {path}")
        status_var.set("Лог збережено 🧾")
    except Exception as e:
        messagebox.showerror("Помилка", str(e))

# ---- core actions ----
def block_action():
    fp = entry_path.get().strip(); note = note_entry.get().strip()
    if not fp or not os.path.isfile(fp):
        messagebox.showerror("Помилка", "Некоректний шлях або файл не існує."); return
    r1, r2 = block_program(db, fp, note)
    if connection_monitor:
        connection_monitor.mark_known(fp)
    append_log(log_text, f"✅ Заблоковано {fp}\nВхід: {r1.returncode}\nВихід: {r2.returncode}")
    status_var.set("Програма заблокована ✅"); reload_blocked_list()

def unblock_action():
    sel = blocked_listbox.curselection()
    if not sel: messagebox.showerror("Помилка", "Оберіть програми для розблокування."); return
    paths = [blocked_listbox.get(i) for i in sel]
    for p in paths:
        try:
            r1, r2 = unblock_program(db, p)
            append_log(log_text, f"🗑 Розблоковано {p}\nВхід: {r1.returncode}\nВихід: {r2.returncode}")
            if connection_monitor:
                connection_monitor.forget(p)
        except Exception as e:
            append_log(log_text, f"❗ Помилка розблокування {p}: {e}")
    status_var.set(f"Розблоковано {len(paths)} програм"); reload_blocked_list()

def update_action():
    sel = blocked_listbox.curselection()
    targets = [blocked_listbox.get(i) for i in sel] if sel else []
    if not targets:
        fp = entry_path.get().strip()
        if fp: targets = [fp]
    if not targets: messagebox.showerror("Помилка", "Вкажіть шлях у полі або оберіть програми зі списку."); return
    ok = 0
    for p in targets:
        try:
            res = update_rule(p)
            if isinstance(res, tuple) and len(res) == 2 and all(hasattr(x,"returncode") for x in res):
                a1,a2 = res
                append_log(log_text, f"🔁 Перевстановлено {p} -> ({a1.returncode},{a2.returncode})")
            else:
                (d1,d2),(a1,a2) = res
                append_log(log_text, f"🔁 Reinstall {p} del({d1.returncode},{d2.returncode}) add({a1.returncode},{a2.returncode})")
            ok += 1
        except Exception as e:
            append_log(log_text, f"❗ Помилка оновлення {p}: {e}")
    status_var.set(f"Оновлено {ok} правил 🔁")

def clear_database():
    if messagebox.askyesno("Очистити базу","Очистити локальну БД? (Правила Windows НЕ змінюються)"):
        clear_db(db); reload_blocked_list(); append_log(log_text,"🧹 База очищена")
        if messagebox.askyesno("Відновити","Відновити з фаєрвола?"): restore_from_firewall_action()
        else: status_var.set("База очищена 🧹")

def restore_from_firewall_action():
    added, total = rebuild_db_from_firewall(db); reload_blocked_list()
    if connection_monitor:
        for rec in db.values():
            path = rec.get("path")
            if path:
                connection_monitor.mark_known(path)
    if total == 0:
        append_log(log_text,"ℹ️ У фаєрволі не знайдено правил Block_*"); status_var.set("Нічого не знайдено")
    else:
        append_log(log_text, f"🔎 Знайдено {total}, додано {added}"); status_var.set(f"Відновлено +{added}")

def reload_blocked_list():
    blocked_listbox.delete(0, tk.END)
    items = list(db.values()); items.sort(key=lambda x:(x.get("path") or "").lower())
    for i in items: blocked_listbox.insert(tk.END, i.get("path") or "")
    status_var.set(f"Список оновлено ({len(items)})")

# ---- import/export/clean ----
def backup_database():
    default_name = f"blocked_list_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    path = filedialog.asksaveasfilename(defaultextension=".json", initialfile=default_name)
    if not path: return
    backup_db(db,path); append_log(log_text, f"💾 Резервну копію збережено: {path}")

def import_database():
    path = filedialog.askopenfilename(filetypes=[("JSON","*.json"),("All","*.*")])
    if not path: return
    ans = messagebox.askyesnocancel("Імпорт","Перезаписувати дублікати?")
    if ans is None: return
    overwrite = bool(ans)
    added,updated,skipped = import_db(db, path, overwrite=overwrite)
    reload_blocked_list(); append_log(log_text, f"📥 Імпорт: +{added} upd{updated} skip{skipped}")

def clean_broken_records():
    missing = [rec.get("path") for rec in db.values() if not rec.get("path") or not os.path.isfile(rec.get("path"))]
    if not missing: messagebox.showinfo("Перевірка","Битих записів не знайдено"); return
    preview = "\n".join([m for m in missing[:10] if m])
    ans = messagebox.askyesnocancel("Знайдені биті записи", f"Знайдено {len(missing)}.\nПерші:\n{preview}")
    if ans is None: return
    keys_to_delete = [k for k,rec in db.items() if rec.get("path") in missing]
    removed_db=0; removed_fw=0
    for k in keys_to_delete:
        path = db[k].get("path")
        if ans and path:
            try:
                r1,r2 = delete_rule_by_path(path)
                if hasattr(r1,"returncode"): removed_fw+=1
            except Exception:
                pass
        del db[k]; removed_db+=1
        if connection_monitor:
            connection_monitor.forget(path)
    save_db(db); reload_blocked_list()
    append_log(log_text, f"🧹 Видалено з БД:{removed_db} правил:{removed_fw}")

# ---- outbound monitor ----
def _format_remote_info(event: dict) -> str:
    remote = event.get("remote_address") or "невідомо"
    port = event.get("remote_port")
    if port:
        return f"{remote}:{port}"
    return str(remote)


def _ask_user_about_connection(path: str, remote_info: str) -> str:
    win = tk.Toplevel(root)
    win.title("Новий вихідний зв'язок")
    win.configure(bg="#1e1e1e")
    win.resizable(False, False)
    message = (
        "Виявлено спробу вихідного підключення від програми:\n\n"
        f"{path}\n\n"
        f"Ціль: {remote_info}\n\n"
        "Що робити?"
    )
    tk.Label(win, text=message, bg="#1e1e1e", fg="#f0f0f0", justify="left", wraplength=520).pack(padx=16, pady=(16, 12))

    result = {"value": "ignore"}

    btns = tk.Frame(win, bg="#1e1e1e")
    btns.pack(fill="x", padx=16, pady=(0, 16))

    def _set(value: str):
        result["value"] = value
        win.destroy()

    tk.Button(btns, text="Дозволити", command=lambda: _set("allow"), width=12, bg="#4caf50", fg="white").pack(side="left", padx=4)
    tk.Button(btns, text="Заблокувати", command=lambda: _set("block"), width=14, bg="#e53935", fg="white").pack(side="left", padx=4)
    tk.Button(btns, text="Ігнорувати", command=lambda: _set("ignore"), width=12, bg="#607d8b", fg="white").pack(side="right", padx=4)

    win.transient(root)
    win.grab_set()
    root.wait_window(win)
    return result["value"]


def handle_outgoing_event(event: dict, monitor_obj):
    path = event.get("path")
    if not path:
        return
    if not os.path.isfile(path):
        monitor_obj.mark_known(path)
        return

    remote_info = _format_remote_info(event)

    decision = _ask_user_about_connection(path, remote_info)
    note = f"auto {remote_info}"

    if decision == "allow":
        try:
            res = allow_program(allow_db, path, note=note)
            append_log(log_text, f"✅ Дозволено {path} -> {res.returncode if hasattr(res,'returncode') else res}")
            status_var.set("Створено дозвіл на вихід")
        except Exception as e:
            messagebox.showerror("Помилка", f"Не вдалося створити правило дозволу:\n{e}")
        finally:
            monitor_obj.mark_known(path)
        return

    if decision == "block":
        try:
            r1, r2 = block_program(db, path, note=note)
            append_log(log_text, f"⛔ Заблоковано {path} ({r1.returncode},{r2.returncode})")
            reload_blocked_list()
            status_var.set("Програму заблоковано через монітор")
        except Exception as e:
            messagebox.showerror("Помилка", f"Не вдалося заблокувати програму:\n{e}")
        finally:
            monitor_obj.mark_known(path)
        return

    monitor_obj.ignore_once(path)
    append_log(log_text, f"ℹ️ Ігноровано підключення {path} ({remote_info})")
    status_var.set("Спробу підключення проігноровано")


def report_monitor_error(msg: str):
    append_log(log_text, f"⚠️ Моніторинг: {msg}")
    status_var.set("Помилка моніторингу")

# ---- process picker ----
def open_process_picker():
    win = tk.Toplevel(root); win.title("🧠 Обрати з процесів"); win.geometry("900x520"); win.configure(bg="#1e1e1e")
    win.resizable(False, False)
    top = tk.Frame(win, bg="#1e1e1e"); top.pack(fill='x', padx=8, pady=6)
    tk.Label(top, text="Фільтр:", bg="#1e1e1e", fg="#f0f0f0").pack(side='left')
    filter_var = tk.StringVar()
    ent = tk.Entry(top, textvariable=filter_var, width=60, bg="#252526", fg="white", insertbackground="white"); ent.pack(side='left', padx=8)
    cols = ("pid","name","path"); tree = ttk.Treeview(win, columns=cols, show="headings", height=18)
    for c,t,w in (("pid","PID",70),("name","Назва",200),("path","Шлях",600)):
        tree.heading(c, text=t); tree.column(c, width=w, anchor="w")
    tree.pack(fill='both', expand=True, padx=8, pady=4)
    sb = tk.Scrollbar(tree, orient="vertical", command=tree.yview); tree.configure(yscrollcommand=sb.set); sb.pack(side="right", fill="y")
    btns = tk.Frame(win, bg="#1e1e1e"); btns.pack(fill='x', padx=8, pady=6)
    tk.Button(btns, text="↪ У поле", width=14, bg="#03a9f4", fg="white", command=lambda: _apply_to_entry()).pack(side='left', padx=5)
    tk.Button(btns, text="➕ Заблокувати вибрані", width=22, bg="#4caf50", fg="white", command=lambda: _block_selected()).pack(side='left', padx=5)
    tk.Button(btns, text="Оновити", width=12, bg="#607d8b", fg="white", command=lambda: _reload()).pack(side='left', padx=5)
    tk.Button(btns, text="Закрити", width=10, bg="#555555", fg="white", command=win.destroy).pack(side='right', padx=5)
    all_items=[]
    def _load(): 
        nonlocal all_items
        all_items = list_running_processes(); _refill()
    def _refill():
        q=(filter_var.get() or "").lower().strip(); tree.delete(*tree.get_children())
        for d in all_items:
            name = d.get("name") or ""; path = d.get("path") or ""
            if q and (q not in name.lower() and q not in path.lower()): continue
            tree.insert("","end", values=(d.get("pid"), name, path))
        status_var.set(f"Процесів: {len(tree.get_children())}")
    def _get_selected_paths():
        sel = tree.selection(); paths=[]
        for it in sel:
            vals = tree.item(it,"values")
            if len(vals)>=3: paths.append(vals[2])
        return paths
    def _apply_to_entry():
        paths=_get_selected_paths()
        if not paths: messagebox.showinfo("Вибір","Оберіть процес"); return
        entry_path.delete(0,tk.END); entry_path.insert(0,paths[0]); status_var.set("Шлях вставлено з процесів")
    def _block_selected():
        paths=_get_selected_paths()
        if not paths: messagebox.showinfo("Вибір","Оберіть процеси"); return
        note = note_entry.get().strip(); ok=0
        for p in paths:
            try:
                if not os.path.isfile(p): append_log(log_text, f"⚠️ Пропущено (нема файлу): {p}"); continue
                r1,r2 = block_program(db,p,note); append_log(log_text, f"✅ Заблоковано {p} ({r1.returncode},{r2.returncode})"); ok+=1
                if connection_monitor:
                    connection_monitor.mark_known(p)
            except Exception as e:
                append_log(log_text, f"❗ Помилка: {e}")
        if ok: reload_blocked_list(); status_var.set(f"Заблоковано {ok}")
    def _reload(): _load()
    filter_var.trace_add("write", lambda *_: _refill()); _load(); ent.focus_set()

# ---- RULE SEARCH window (with export/hotkeys/mass reinstall/autosync) ----
def open_rule_search():
    win = tk.Toplevel(root); win.title("🔍 Пошук правил фаєрвола"); win.geometry("980x640"); win.configure(bg="#1e1e1e")
    bar = tk.Frame(win, bg="#1e1e1e"); bar.pack(fill="x", padx=8, pady=6)
    tk.Label(bar, text="Запит:", bg="#1e1e1e", fg="#f0f0f0").pack(side="left")
    q_var = tk.StringVar(); q_entry = tk.Entry(bar, textvariable=q_var, width=48, bg="#252526", fg="white", insertbackground="white"); q_entry.pack(side="left", padx=6)
    tk.Label(bar, text="Напрям:", bg="#1e1e1e", fg="#f0f0f0").pack(side="left", padx=(12,2))
    dir_var = tk.StringVar(value="усі")
    dir_combo = ttk.Combobox(bar, textvariable=dir_var, width=8, values=["усі","вхід","вихід"], state="readonly"); dir_combo.pack(side="left")
    tk.Button(bar, text="Оновити", bg="#607d8b", fg="white", command=lambda:_refresh()).pack(side="left", padx=6)
    tk.Button(bar, text="Експорт TXT", bg="#00bcd4", fg="black", command=lambda:_export_txt()).pack(side="right", padx=6)
    tk.Button(bar, text="Експорт JSON", bg="#0097a7", fg="white", command=lambda:_export_json()).pack(side="right", padx=6)
    tk.Button(bar, text="Reinstall вибраних", bg="#ff9800", fg="black", command=lambda:_mass_reinstall()).pack(side="right", padx=6)
    tk.Button(bar, text="Видалити вибрані", bg="#e53935", fg="white", command=lambda:_delete_selected()).pack(side="right", padx=6)

    cols = ("name","dir","action","enabled","program")
    tree = ttk.Treeview(win, columns=cols, show="headings")
    tree.heading("name", text="Назва"); tree.column("name", width=360, anchor="w")
    tree.heading("dir", text="Напрям"); tree.column("dir", width=70, anchor="center")
    tree.heading("action", text="Дія"); tree.column("action", width=80, anchor="center")
    tree.heading("enabled", text="Стан"); tree.column("enabled", width=70, anchor="center")
    tree.heading("program", text="Програма"); tree.column("program", width=360, anchor="w")
    tree.pack(fill="both", expand=True, padx=8, pady=6)
    sb = ttk.Scrollbar(tree, orient="vertical", command=tree.yview); tree.configure(yscrollcommand=sb.set); sb.pack(side="right", fill="y")
    status = tk.Label(win, text="", bg="#1e1e1e", fg="#9f9f9f", anchor="w"); status.pack(fill="x", padx=8, pady=(0,6))

    results_cache = []

    def _refresh():
        tree.delete(*tree.get_children())
        query = (q_var.get() or "").lower().strip()
        dsel = dir_var.get(); dfilter=None
        if dsel=="вхід": dfilter="in"
        elif dsel=="вихід": dfilter="out"
        try:
            rules = _list_rules(dir_filter=dfilter)
        except Exception as e:
            messagebox.showerror("Помилка читання правил", str(e)); return
        rows=[]
        for r in rules:
            name = r.get("Rule Name",""); direction=(r.get("Direction") or "").capitalize()
            action = r.get("Action",""); enabled=r.get("Enabled",""); program=r.get("Program","")
            blob = " ".join([name,direction,action,enabled,program]).lower()
            if query and query not in blob: continue
            rows.append((name,direction,action,enabled,program,r))
        rows.sort(key=lambda x:(x[0].lower(), x[1]))
        for (name,direction,action,enabled,program,r) in rows:
            tree.insert("","end", values=(name,direction,action,enabled,program))
        nonlocal results_cache; results_cache = rows
        status.config(text=f"Знайдено: {len(rows)}")

    def _selected_rules():
        sel=[]; selected_vals=[tree.item(i,"values") for i in tree.selection()]
        for vals in selected_vals:
            if len(vals)<5: continue
            name,direction,action,enabled,program = vals
            for tup in results_cache:
                if tup[0]==name and tup[1]==direction and tup[4]==program:
                    sel.append(tup[-1]); break
        return sel

    def _export_txt():
        if not results_cache:
            messagebox.showinfo("Експорт","Немає результатів для експорту"); return
        default = f"rules_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=default)
        if not path: return
        try:
            with open(path,"w",encoding="utf-8") as f:
                for (name,direction,action,enabled,program,r) in results_cache:
                    f.write(f"{name}\t{direction}\t{action}\t{enabled}\t{program}\n")
            append_log(log_text, f"📄 Rules exported (TXT): {path}")
            status.config(text="Експортовано у TXT")
        except Exception as e:
            messagebox.showerror("Помилка експорту", str(e))

    def _export_json():
        if not results_cache:
            messagebox.showinfo("Експорт","Немає результатів для експорту"); return
        default = f"rules_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path = filedialog.asksaveasfilename(defaultextension=".json", initialfile=default)
        if not path: return
        try:
            out = []
            for (name,direction,action,enabled,program,r) in results_cache:
                out.append({"name":name,"direction":direction,"action":action,"enabled":enabled,"program":program})
            with open(path,"w",encoding="utf-8") as f: json.dump(out,f,ensure_ascii=False,indent=2)
            append_log(log_text, f"📄 Rules exported (JSON): {path}")
            status.config(text="Експортовано у JSON")
        except Exception as e:
            messagebox.showerror("Помилка експорту", str(e))

    def _mass_reinstall():
        sel = _selected_rules()
        if not sel:
            messagebox.showinfo("Reinstall","Оберіть правила з Program щоб перевстановити"); return
        if not messagebox.askyesno("Підтвердження","Перевстановити вибрані правила (за Program)?"):
            return
        ok=0
        for r in sel:
            prog = r.get("Program")
            if not prog or not os.path.isfile(prog):
                append_log(log_text, f"⚠️ Пропущено (програма відсутня): {prog}")
                continue
            try:
                update_rule(prog)
                append_log(log_text, f"🔁 Reinstall for program: {prog}")
                ok+=1
            except Exception as e:
                append_log(log_text, f"❗ Помилка reinstall {prog}: {e}")
        append_log(log_text, f"Reinstall завершено: {ok}")
        status.config(text=f"Reinstall: {ok}")
        try:
            rebuild_db_from_firewall(db); reload_blocked_list()
            append_log(log_text, "🔁 БД синхронизовано після Reinstall")
        except Exception as e:
            append_log(log_text, f"Помилка синхронізації БД: {e}")

    def _delete_selected():
        sel = _selected_rules()
        if not sel: messagebox.showinfo("Видалення","Оберіть правило(а)"); return
        if not messagebox.askyesno("Підтвердження", f"Видалити {len(sel)} правило(а)?"): return
        ok=0
        for r in sel:
            good,out = _delete_rule_precise(r)
            append_log(log_text, out or ("OK" if good else "Помилка"))
            if good: ok+=1
        status.config(text=f"Видалено: {ok}")
        _refresh()
        try:
            rebuild_db_from_firewall(db); reload_blocked_list()
            append_log(log_text, "🔁 БД синхронизовано після видалення правил")
        except Exception as e:
            append_log(log_text, f"Помилка синхронізації БД: {e}")

    # hotkeys
    def on_key(e):
        if e.keysym == "Return": _refresh()
        elif e.keysym == "Delete": _delete_selected()
        elif (e.state & 0x4) and e.keysym.lower() == "s": _export_txt()  # Ctrl+S
    q_entry.bind("<Key>", on_key)

    _refresh(); q_entry.focus_set()

# ---- context menu for blocked list ----
def list_context_menu(event):
    if not blocked_listbox.size(): return
    try:
        index = blocked_listbox.nearest(event.y); blocked_listbox.selection_clear(0,tk.END); blocked_listbox.selection_set(index)
    except Exception:
        pass
    menu = tk.Menu(root, tearoff=0)
    menu.add_command(label="Копіювати шлях", command=copy_selected_path)
    menu.add_command(label="Відкрити папку", command=open_folder_of_selected)
    menu.add_command(label="Показати в Провіднику", command=reveal_in_explorer)
    try:
        menu.tk_popup(event.x_root, event.y_root)
    finally:
        menu.grab_release()

def get_selected_path():
    sel = blocked_listbox.curselection(); return blocked_listbox.get(sel[0]) if sel else None

def copy_selected_path():
    p = get_selected_path()
    if not p: return
    root.clipboard_clear(); root.clipboard_append(p); status_var.set("Скопійовано шлях")

def open_folder_of_selected():
    p = get_selected_path()
    if not p: return
    folder = os.path.dirname(p)
    if os.path.isdir(folder):
        try: os.startfile(folder)
        except Exception as e: messagebox.showerror("Помилка", str(e))
    else:
        messagebox.showerror("Помилка", "Папка не існує.")

def reveal_in_explorer():
    p = get_selected_path(); 
    if not p: return
    try:
        subprocess.run(['explorer', f'/select,"{p}"'], check=False)
    except Exception:
        try: os.startfile(os.path.dirname(p))
        except Exception as e: messagebox.showerror("Помилка", str(e))

# ---- build main window ----
root = tk.Tk(); root.title("🔒 Firewall Manager"); root.geometry("1000x800"); root.configure(bg="#1e1e1e"); root.resizable(True,True)

# menu
menubar = tk.Menu(root)
file_menu = tk.Menu(menubar, tearoff=0)
file_menu.add_command(label="Згорнути в трей", command=lambda: minimize_to_tray())
file_menu.add_separator()
file_menu.add_command(label="Вихід", command=lambda: exit_app(confirm=False))
menubar.add_cascade(label="Файл", menu=file_menu)
settings_menu = tk.Menu(menubar, tearoff=0)
settings_menu.add_command(label="Резервне копіювання бази…", command=backup_database)
settings_menu.add_command(label="Імпорт бази…", command=import_database)
settings_menu.add_separator()
settings_menu.add_command(label="Очистити “биті” записи…", command=clean_broken_records)
settings_menu.add_command(label="Відновити зі фаєрвола", command=restore_from_firewall_action)
menubar.add_cascade(label="Налаштування", menu=settings_menu); root.config(menu=menubar)

install_shortcuts(root)

# presets UI
presets_frame = tk.Frame(root, bg="#1e1e1e"); presets_frame.pack(fill='x', padx=10, pady=(8,0))
presets_label = tk.Label(presets_frame, text="Швидкі пресети:", bg="#1e1e1e", fg="#d0f0ff"); presets_label.pack(side='left')
def rebuild_presets_ui():
    for w in presets_frame.pack_slaves():
        if getattr(w,"_is_preset_btn",False): w.destroy()
    for idx,p in enumerate(presets):
        def _make_cb(p=p): entry_path.delete(0,tk.END); entry_path.insert(0,p.get("path",""))
        b = tk.Button(presets_frame, text=p.get("name","?"), command=_make_cb, bg="#2e3b3f", fg="white")
        b._is_preset_btn = True; b.pack(side='left', padx=4)
        def _rm(idx=idx):
            if messagebox.askyesno("Видалити пресет", f"Видалити пресет {presets[idx].get('name')}?"):
                remove_preset(idx)
        rb = tk.Button(presets_frame, text="✖", command=_rm, bg="#4a2f2f", fg="white")
        rb._is_preset_btn = True; rb.pack(side='left', padx=(0,6))
rebuild_presets_ui()
def _add_preset_dialog():
    ppath = entry_path.get().strip()
    if not ppath:
        messagebox.showinfo("Додати пресет","Вкажи шлях у полі")
        return
    name = os.path.basename(ppath)
    add_preset(name, ppath)
tk.Button(presets_frame, text="➕ Додати пресет", command=_add_preset_dialog, bg="#33691e", fg="white").pack(side='left')

top_frame = tk.Frame(root, bg="#1e1e1e"); top_frame.pack(fill='x', padx=10, pady=6)
tk.Label(top_frame, text="Шлях до файлу (.exe):", bg="#1e1e1e", fg="#f0f0f0").pack(side='left')
entry_path = tk.Entry(top_frame, width=80, bg="#252526", fg="white", insertbackground="white"); entry_path.pack(side='left', padx=6)
tk.Button(top_frame, text="Обрати файл", command=select_file, width=14, bg="#007acc", fg="white").pack(side='left', padx=4)
tk.Button(top_frame, text="З процесів…", command=open_process_picker, width=14, bg="#8e24aa", fg="white").pack(side='left', padx=4)
tk.Button(top_frame, text="🔍 Пошук правил", command=open_rule_search, width=16, bg="#00bcd4", fg="black").pack(side='right', padx=4)

tk.Label(root, text="Примітка (опційно):", bg="#1e1e1e", fg="#f0f0f0").pack(pady=(6,2))
note_entry = tk.Entry(root, width=110, bg="#252526", fg="white", insertbackground="white"); note_entry.pack(pady=(0,6))

btn_frame = tk.Frame(root, bg="#1e1e1e"); btn_frame.pack(pady=8, padx=10, fill='x')
tk.Button(btn_frame, text="➕ Заблокувати", command=block_action, width=18, bg="#4caf50", fg="white").grid(row=0,column=0,padx=5,pady=5,sticky="nsew")
tk.Button(btn_frame, text="❌ Розблокувати вибране", command=unblock_action, width=22, bg="#e53935", fg="white").grid(row=0,column=1,padx=5,pady=5,sticky="nsew")
tk.Button(btn_frame, text="🔁 Перевстановити правило(а)", command=update_action, width=22, bg="#fbc02d", fg="black").grid(row=0,column=2,padx=5,pady=5,sticky="nsew")
tk.Button(btn_frame, text="🧹 Очистити базу", command=clear_database, width=16, bg="#9c27b0", fg="white").grid(row=0,column=3,padx=5,pady=5,sticky="nsew")
# NEW: restore button on main panel
tk.Button(btn_frame, text="🔄 Відновити зі фаєрвола", command=restore_from_firewall_action, width=20, bg="#1976d2", fg="white").grid(row=0,column=4,padx=5,pady=5,sticky="nsew")
for i in range(5): btn_frame.columnconfigure(i, weight=1)

# main panes
main_pane = tk.PanedWindow(root, orient="vertical", sashwidth=6, sashrelief="raised", bg="#1e1e1e"); main_pane.pack(fill="both", expand=True, padx=10, pady=6)
list_frame = tk.Frame(main_pane, bg="#1e1e1e"); blocked_listbox = tk.Listbox(list_frame, selectmode="extended", bg="#252526", fg="white", font=("Consolas",10)); blocked_listbox.pack(side='left', fill='both', expand=True)
blocked_listbox.bind("<Button-3>", list_context_menu)
scrollbar = tk.Scrollbar(list_frame, command=blocked_listbox.yview); scrollbar.pack(side='right', fill='y'); blocked_listbox.config(yscrollcommand=scrollbar.set)
main_pane.add(list_frame, stretch="always")
log_frame = tk.LabelFrame(main_pane, text="Лог", bg="#1e1e1e", fg="#00bcd4"); log_text = scrolledtext.ScrolledText(log_frame, state='disabled', wrap='word', bg="#252526", fg="#f1f1f1"); log_text.pack(fill='both', expand=True); main_pane.add(log_frame, stretch="always")

bottom_frame = tk.Frame(root, bg="#1e1e1e"); bottom_frame.pack(fill='x', padx=10, pady=6)
tk.Button(bottom_frame, text="📥 У трей", command=minimize_to_tray, width=16, bg="#455a64", fg="white").pack(side='left', padx=5)
tk.Button(bottom_frame, text="🧽 Очистити лог", command=clear_log, width=16, bg="#ff9800", fg="white").pack(side='right', padx=5)
tk.Button(bottom_frame, text="🧾 Зберегти лог…", command=save_log_to_file, width=16, bg="#8bc34a", fg="black").pack(side='right', padx=5)

status_var = tk.StringVar(value="Готово."); status_bar = tk.Label(root, textvariable=status_var, relief='sunken', anchor='w', bg="#333", fg="#ccc"); status_bar.pack(side='bottom', fill='x')


def show_main_window():
    root.deiconify()
    try:
        root.after(0, root.focus_force)
    except Exception:
        pass
    if tray_controller and tray_controller.is_available():
        tray_controller.hide()
    status_var.set("Головне вікно активне")


def minimize_to_tray():
    global tray_controller
    if tray_controller and tray_controller.is_available():
        root.withdraw()
        tray_controller.show()
        status_var.set("NetshLite працює у треї")
    else:
        root.iconify()
        status_var.set("Згорнуто у вікно")


def exit_app(confirm: bool = True):
    global connection_monitor, tray_controller
    if confirm and not messagebox.askokcancel("Вихід", "Завершити NetshLite?"):
        return
    if connection_monitor:
        try:
            connection_monitor.stop()
        except Exception:
            pass
        connection_monitor = None
    if tray_controller:
        try:
            tray_controller.stop()
        except Exception:
            pass
    root.destroy()


def on_close():
    if tray_controller and tray_controller.is_available():
        minimize_to_tray()
    else:
        exit_app(confirm=False)


def on_monitor_event(event, mon):
    root.after(0, lambda ev=event, mm=mon: handle_outgoing_event(ev, mm))


def on_monitor_error(msg: str):
    root.after(0, lambda: report_monitor_error(msg))


initial_known = [rec.get("path") for rec in db.values() if rec.get("path")] + [rec.get("path") for rec in allow_db.values() if rec.get("path")]
connection_monitor = OutboundConnectionMonitor(initial_known, on_monitor_event, on_monitor_error)
connection_monitor.start()

tray_controller = TrayController(
    tooltip="NetshLite Firewall Manager",
    on_show=lambda: root.after(0, show_main_window),
    on_exit=lambda: root.after(0, exit_app, False),
)
if tray_controller.start():
    tray_controller.hide()
root.protocol("WM_DELETE_WINDOW", on_close)

reload_blocked_list()
show_main_window()
root.mainloop()
