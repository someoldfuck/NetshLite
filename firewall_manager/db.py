import json
import os

DB_FILE = "blocked_list.json"

def load_db():
    if not os.path.exists(DB_FILE):
        return {}
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_db(db: dict):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

def clear_db(db: dict):
    db.clear()
    save_db(db)

def backup_db(db: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

def import_db(db: dict, path: str, overwrite: bool = False):
    """
    Імпортує дані з JSON-файлу у поточну базу.
    - overwrite=True  -> перезаписувати існуючі ключі
    - overwrite=False -> зберігати існуючі, додавати лише нові
    Повертає (added, updated, skipped).
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            incoming = json.load(f)
    except Exception as e:
        raise RuntimeError(f"Не вдалося прочитати JSON: {e}")

    if not isinstance(incoming, dict):
        raise RuntimeError("Невірний формат: очікується dict {hash: {path,time,note}}")

    added = updated = skipped = 0
    for k, v in incoming.items():
        if k in db:
            if overwrite:
                db[k] = v
                updated += 1
            else:
                skipped += 1
        else:
            db[k] = v
            added += 1

    save_db(db)
    return added, updated, skipped
