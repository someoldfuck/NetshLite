import json
import os
from datetime import datetime

ALLOW_DB_FILE = "allowed_list.json"


def load_allow_db():
    if not os.path.exists(ALLOW_DB_FILE):
        return {}
    try:
        with open(ALLOW_DB_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def save_allow_db(db: dict):
    with open(ALLOW_DB_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)


def add_allow_record(db: dict, key: str, path: str, note: str = ""):
    db[key] = {
        "path": path,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "note": note,
    }
    save_allow_db(db)


def delete_allow_record(db: dict, key: str):
    if key in db:
        del db[key]
        save_allow_db(db)
