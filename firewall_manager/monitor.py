import json
import os
import re
import subprocess
import threading
from typing import Callable, Iterable, Optional

from .utils import sha1

_EVENT_PATH_RE = re.compile(r"Application Path:\s*(.+)$", re.MULTILINE)
_EVENT_PROGRAM_RE = re.compile(r"Program:\s*(.+)$", re.MULTILINE)
_EVENT_REMOTE_RE = re.compile(r"Remote\s+(?:Address|IP):\s*([^\s]+)")
_EVENT_PORT_RE = re.compile(r"Remote\s+(?:Port|Port Number):\s*(\d+)")


class OutboundConnectionMonitor:
    """Streams firewall events about blocked outbound connections.

    Uses PowerShell ``Get-WinEvent`` to wait for events from
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
    with IDs 2004 and 2006. Those events contain the ``Application Path``
    field that we use to map attempts to executable paths.
    """

    def __init__(
        self,
        known_paths: Iterable[str],
        callback: Optional[Callable[[dict, "OutboundConnectionMonitor"], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
    ):
        self._known_hashes = set()
        for p in known_paths or []:
            if p:
                self._known_hashes.add(sha1(p))
        self._callback = callback
        self._on_error = on_error
        self._lock = threading.RLock()
        self._ignore_once = set()
        self._thread: Optional[threading.Thread] = None
        self._proc: Optional[subprocess.Popen] = None
        self._stopping = threading.Event()

    def start(self):
        if os.name != "nt":
            return
        if self._thread and self._thread.is_alive():
            return
        self._stopping.clear()
        self._thread = threading.Thread(target=self._worker, name="FirewallMonitor", daemon=True)
        self._thread.start()

    def stop(self):
        self._stopping.set()
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass
            try:
                self._proc.kill()
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    # ---- coordination helpers ----
    def mark_known(self, path: str):
        if not path:
            return
        with self._lock:
            self._known_hashes.add(sha1(path))
            self._ignore_once.discard(path.lower())

    def ignore_once(self, path: str):
        if not path:
            return
        with self._lock:
            self._ignore_once.add(path.lower())

    def forget(self, path: str):
        if not path:
            return
        with self._lock:
            self._known_hashes.discard(sha1(path))
            self._ignore_once.discard(path.lower())

    # ---- internal ----
    def _should_skip(self, path: Optional[str]) -> bool:
        if not path:
            return True
        h = sha1(path)
        with self._lock:
            if h in self._known_hashes:
                return True
            if path.lower() in self._ignore_once:
                return True
        return False

    def _worker(self):
        script = (
            "$ErrorActionPreference = 'SilentlyContinue';"
            "$filter = @{LogName='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; ID=2004,2006};"
            "while ($true) {"
            "  if ($Host.UI.RawUI.KeyAvailable) { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown'); }"
            "  $event = Get-WinEvent -FilterHashtable $filter -MaxEvents 1 -Wait;"
            "  if ($null -eq $event) { continue }"
            "  $payload = [PSCustomObject]@{"
            "    Time = $event.TimeCreated.ToString('o');"
            "    Id = $event.Id;"
            "    Message = $event.Message;"
            "  };"
            "  $payload | ConvertTo-Json -Compress;"
            "}"
        )
        try:
            self._proc = subprocess.Popen(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    script,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except FileNotFoundError:
            if self._on_error:
                self._on_error("PowerShell не знайдено. Моніторинг подій вимкнено.")
            return
        except Exception as exc:
            if self._on_error:
                self._on_error(f"Не вдалося запустити PowerShell: {exc}")
            return

        while not self._stopping.is_set() and self._proc.poll() is None:
            line = self._proc.stdout.readline()
            if not line:
                if self._proc.poll() is not None or self._stopping.is_set():
                    break
                continue
            try:
                data = json.loads(line)
            except Exception:
                continue
            message = data.get("Message") or ""
            path = self._extract_path(message)
            if self._should_skip(path):
                continue
            event = {
                "path": path,
                "time": data.get("Time"),
                "event_id": data.get("Id"),
                "remote_address": self._extract_remote(message),
                "remote_port": self._extract_port(message),
                "message": message,
            }
            if self._callback:
                try:
                    self._callback(event, self)
                except Exception:
                    if self._on_error:
                        self._on_error("Помилка обробки події")
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass

    @staticmethod
    def _extract_path(message: str) -> Optional[str]:
        if not message:
            return None
        match = _EVENT_PATH_RE.search(message)
        if not match:
            match = _EVENT_PROGRAM_RE.search(message)
        if match:
            return match.group(1).strip().strip('"')
        return None

    @staticmethod
    def _extract_remote(message: str) -> Optional[str]:
        if not message:
            return None
        match = _EVENT_REMOTE_RE.search(message)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def _extract_port(message: str) -> Optional[int]:
        if not message:
            return None
        match = _EVENT_PORT_RE.search(message)
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                return None
        return None
