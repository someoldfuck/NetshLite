import json
import os
import subprocess
import threading
from typing import Callable, Iterable, Optional

from .utils import sha1


class OutboundConnectionMonitor:
    """Watches live TCP connections and reports unknown executables.

    On Windows the monitor runs a lightweight PowerShell loop around
    ``Get-NetTCPConnection`` and ``Get-Process``.  Whenever a new outbound
    connection with a previously unseen executable path is detected, the
    provided callback is invoked with a rich event payload.  Callers are
    expected to mark the path as known (``mark_known``) once a decision is
    made so we do not prompt for the same executable again.
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
        self._skip_hosts = {
            "0.0.0.0",
            "127.0.0.1",
            "::1",
            "::",
        }
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
        lp = path.lower()
        with self._lock:
            if h in self._known_hashes:
                return True
            if lp in self._ignore_once:
                self._ignore_once.discard(lp)
                return True
        return False

    def _should_skip_remote(self, remote: Optional[str]) -> bool:
        if not remote:
            return False
        return remote in self._skip_hosts or remote.lower().startswith("fe80:")

    def _worker(self):
        script = """
$ErrorActionPreference = 'SilentlyContinue'
$seen = @{}
while ($true) {
  try {
    $conns = Get-NetTCPConnection -State Established -ErrorAction Stop
  } catch {
    Start-Sleep -Milliseconds 800
    continue
  }
  $current = @{}
  foreach ($conn in $conns) {
    $pid = $conn.OwningProcess
    if (-not $pid) { continue }
    $key = "$($pid)|$($conn.RemoteAddress)|$($conn.RemotePort)"
    $current[$key] = $true
    if ($seen.ContainsKey($key)) { continue }
    try {
      $proc = Get-Process -Id $pid -ErrorAction Stop
    } catch {
      continue
    }
    $path = $proc.Path
    if (-not $path) { continue }
    $seen[$key] = $true
    [PSCustomObject]@{
      Time = [DateTime]::Now.ToString('o')
      Path = $path
      Pid = $pid
      RemoteAddress = $conn.RemoteAddress
      RemotePort = $conn.RemotePort
      Protocol = $conn.Protocol
      State = $conn.State
    } | ConvertTo-Json -Compress
  }
  foreach ($entry in @($seen.Keys)) {
    if (-not $current.ContainsKey($entry)) {
      $seen.Remove($entry) | Out-Null
    }
  }
  Start-Sleep -Milliseconds 700
}
"""
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
            path = data.get("Path")
            if self._should_skip(path):
                continue
            remote_addr = data.get("RemoteAddress")
            if self._should_skip_remote(remote_addr):
                continue
            event = {
                "path": path,
                "time": data.get("Time"),
                "pid": data.get("Pid"),
                "remote_address": remote_addr,
                "remote_port": data.get("RemotePort"),
                "protocol": data.get("Protocol"),
                "state": data.get("State"),
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
