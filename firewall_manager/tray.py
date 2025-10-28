import ctypes
from ctypes import wintypes
import os
import queue
import threading
from typing import Callable, Optional

try:  # pragma: no cover - optional dependency
    import pystray
    from PIL import Image, ImageDraw
except Exception:  # pragma: no cover - optional dependency
    pystray = None
    Image = None
    ImageDraw = None


class _BaseBackend:
    def start(self) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    def stop(self):  # pragma: no cover - interface
        raise NotImplementedError

    def show(self):  # pragma: no cover - interface
        raise NotImplementedError

    def hide(self):  # pragma: no cover - interface
        raise NotImplementedError

    def is_available(self) -> bool:
        return False


class _NullBackend(_BaseBackend):
    def start(self) -> bool:
        return False

    def stop(self):
        pass

    def show(self):
        pass

    def hide(self):
        pass


class _PystrayBackend(_BaseBackend):
    def __init__(self, tooltip: str, on_show: Callable[[], None], on_exit: Callable[[], None]):
        self.tooltip = tooltip
        self.on_show = on_show
        self.on_exit = on_exit
        self._icon: Optional[pystray.Icon] = None if pystray else None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        if not pystray or not Image:
            return False
        if self._icon:
            return True
        image = self._create_image()
        menu = pystray.Menu(
            pystray.MenuItem("Відкрити", lambda: self._invoke(self.on_show)),
            pystray.MenuItem("Вийти", lambda: self._invoke(self.on_exit)),
        )
        self._icon = pystray.Icon("netshlite", image, self.tooltip, menu)
        self._thread = threading.Thread(target=self._icon.run, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        if not self._icon:
            return
        try:
            self._icon.stop()
        except Exception:
            pass
        self._icon = None

    def show(self):
        if self._icon:
            self._icon.visible = True

    def hide(self):
        if self._icon:
            self._icon.visible = False

    def is_available(self) -> bool:
        return bool(pystray and Image)

    def _create_image(self):
        size = 64
        image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        draw.ellipse((6, 6, size - 6, size - 6), fill="#1976d2", outline="#0d47a1", width=4)
        draw.rectangle((size // 2 - 6, 16, size // 2 + 6, size - 16), fill="#ffffff")
        draw.rectangle((16, size // 2 - 6, size - 16, size // 2 + 6), fill="#ffffff")
        return image

    @staticmethod
    def _invoke(cb: Callable[[], None]):
        try:
            cb()
        except Exception:
            pass


class _NativeBackend(_BaseBackend):
    """Fallback Windows native tray implementation using ctypes."""

    def __init__(self, tooltip: str, on_show: Callable[[], None], on_exit: Callable[[], None]):
        self.tooltip = tooltip
        self.on_show = on_show
        self.on_exit = on_exit
        self._thread: Optional[threading.Thread] = None
        self._hwnd = None
        self._queue: "queue.Queue[str]" = queue.Queue()
        self._ready = threading.Event()
        self._running = threading.Event()

    def start(self) -> bool:
        if os.name != "nt":
            return False
        if self._thread and self._thread.is_alive():
            return True
        self._ready.clear()
        self._running.set()
        self._thread = threading.Thread(target=self._loop, name="TrayNative", daemon=True)
        self._thread.start()
        return self._ready.wait(timeout=2.5)

    def stop(self):
        if not self._running.is_set():
            return
        self._running.clear()
        if self._hwnd:
            try:
                from ctypes import windll

                windll.user32.PostMessageW(self._hwnd, 0x0010, 0, 0)  # WM_CLOSE
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    def show(self):
        if self._hwnd:
            try:
                self._queue.put_nowait("show")
            except queue.Full:
                pass
            self._poke()

    def hide(self):
        if self._hwnd:
            try:
                self._queue.put_nowait("hide")
            except queue.Full:
                pass
            self._poke()

    def is_available(self) -> bool:
        return os.name == "nt"

    # ---- internal helpers ----
    def _poke(self):
        try:
            from ctypes import windll

            windll.user32.PostMessageW(self._hwnd, 0x0400 + 7, 0, 0)  # custom nudge message
        except Exception:
            pass

    def _loop(self):  # pragma: no cover - platform specific
        WM_TRAYICON = 0x8000 + 1
        WM_DESTROY = 0x0002
        WM_COMMAND = 0x0111
        WM_USER_POKE = 0x0400 + 7
        WM_LBUTTONUP = 0x0202
        WM_LBUTTONDBLCLK = 0x0203
        WM_RBUTTONUP = 0x0205

        NIF_MESSAGE = 0x00000001
        NIF_ICON = 0x00000002
        NIF_TIP = 0x00000004
        NIF_STATE = 0x00000008
        NIS_HIDDEN = 0x00000001
        NIM_ADD = 0x00000000
        NIM_MODIFY = 0x00000001
        NIM_DELETE = 0x00000002

        ID_CMD_SHOW = 1001
        ID_CMD_EXIT = 1002

        class NOTIFYICONDATA(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("hWnd", wintypes.HWND),
                ("uID", wintypes.UINT),
                ("uFlags", wintypes.UINT),
                ("uCallbackMessage", wintypes.UINT),
                ("hIcon", wintypes.HICON),
                ("szTip", wintypes.WCHAR * 128),
                ("dwState", wintypes.DWORD),
                ("dwStateMask", wintypes.DWORD),
                ("szInfo", wintypes.WCHAR * 256),
                ("uTimeoutOrVersion", wintypes.UINT),
                ("szInfoTitle", wintypes.WCHAR * 64),
                ("dwInfoFlags", wintypes.DWORD),
                ("guidItem", ctypes.c_byte * 16),
                ("hBalloonIcon", wintypes.HICON),
            ]

        class WNDCLASS(ctypes.Structure):
            pass

        WNDPROCTYPE = ctypes.WINFUNCTYPE(
            wintypes.LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
        )

        WNDCLASS._fields_ = [
            ("style", wintypes.UINT),
            ("lpfnWndProc", WNDPROCTYPE),
            ("cbClsExtra", ctypes.c_int),
            ("cbWndExtra", ctypes.c_int),
            ("hInstance", wintypes.HINSTANCE),
            ("hIcon", wintypes.HICON),
            ("hCursor", wintypes.HCURSOR),
            ("hbrBackground", wintypes.HBRUSH),
            ("lpszMenuName", wintypes.LPCWSTR),
            ("lpszClassName", wintypes.LPCWSTR),
        ]

        user32 = ctypes.windll.user32
        shell32 = ctypes.windll.shell32
        kernel32 = ctypes.windll.kernel32

        nid = None
        hwnd = None

        def _invoke(cb: Callable[[], None]):
            try:
                cb()
            except Exception:
                pass

        def _show_menu(window):
            menu = user32.CreatePopupMenu()
            user32.AppendMenuW(menu, 0, ID_CMD_SHOW, "Відкрити")
            user32.AppendMenuW(menu, 0, ID_CMD_EXIT, "Вийти")
            pt = wintypes.POINT()
            user32.GetCursorPos(ctypes.byref(pt))
            user32.SetForegroundWindow(window)
            cmd = user32.TrackPopupMenu(menu, 0x0100, pt.x, pt.y, 0, window, None)
            user32.PostMessageW(window, 0, 0, 0)
            user32.DestroyMenu(menu)
            if cmd == ID_CMD_SHOW:
                _invoke(self.on_show)
            elif cmd == ID_CMD_EXIT:
                _invoke(self.on_exit)

        def wnd_proc(window, msg, wparam, lparam):
            nonlocal nid
            if msg == WM_TRAYICON:
                if lparam in (WM_LBUTTONUP, WM_LBUTTONDBLCLK):
                    _invoke(self.on_show)
                elif lparam == WM_RBUTTONUP:
                    _show_menu(window)
                return 0
            if msg == WM_COMMAND:
                cmd_id = wparam & 0xFFFF
                if cmd_id == ID_CMD_SHOW:
                    _invoke(self.on_show)
                elif cmd_id == ID_CMD_EXIT:
                    _invoke(self.on_exit)
                return 0
            if msg == WM_USER_POKE and nid is not None:
                self._drain_commands(shell32, window, nid)
                return 0
            if msg == WM_DESTROY:
                user32.PostQuitMessage(0)
                return 0
            return user32.DefWindowProcW(window, msg, wparam, lparam)

        try:
            wnd_proc_pointer = WNDPROCTYPE(wnd_proc)

            hinst = kernel32.GetModuleHandleW(None)
            class_name = "NetshLiteTrayWnd"

            wndclass = WNDCLASS()
            wndclass.style = 0
            wndclass.lpfnWndProc = wnd_proc_pointer
            wndclass.cbClsExtra = wndclass.cbWndExtra = 0
            wndclass.hInstance = hinst
            wndclass.hIcon = user32.LoadIconW(None, 32512)
            wndclass.hCursor = user32.LoadCursorW(None, 32512)
            wndclass.hbrBackground = 0
            wndclass.lpszMenuName = None
            wndclass.lpszClassName = class_name

            atom = user32.RegisterClassW(ctypes.byref(wndclass))
            if not atom and kernel32.GetLastError() != 1410:
                return

            hwnd = user32.CreateWindowExW(
                0,
                class_name,
                "NetshLiteTray",
                0,
                0,
                0,
                0,
                0,
                None,
                None,
                hinst,
                None,
            )
            if not hwnd:
                return

            self._hwnd = hwnd

            nid = NOTIFYICONDATA()
            nid.cbSize = ctypes.sizeof(NOTIFYICONDATA)
            nid.hWnd = hwnd
            nid.uID = 1
            nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_STATE
            nid.uCallbackMessage = WM_TRAYICON
            nid.hIcon = user32.LoadIconW(None, 32512)
            nid.dwState = NIS_HIDDEN
            nid.dwStateMask = NIS_HIDDEN
            nid.szTip = self.tooltip[:127]

            if not shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid)):
                return

            self._ready.set()

            msg = wintypes.MSG()
            while self._running.is_set():
                res = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if res == 0 or res == -1:
                    break
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        finally:
            try:
                if nid is not None:
                    shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))
            except Exception:
                pass
            try:
                if hwnd:
                    user32.DestroyWindow(hwnd)
            except Exception:
                pass
            self._hwnd = None
            self._running.clear()
            self._ready.set()

    def _drain_commands(self, shell32, hwnd, nid):  # pragma: no cover - platform specific
        NIM_MODIFY = 0x00000001
        NIF_STATE = 0x00000008
        NIS_HIDDEN = 0x00000001

        while True:
            try:
                cmd = self._queue.get_nowait()
            except queue.Empty:
                break
            if cmd == "show":
                nid.dwState &= ~NIS_HIDDEN
            elif cmd == "hide":
                nid.dwState |= NIS_HIDDEN
            else:
                continue
            nid.dwStateMask = NIS_HIDDEN
            shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))


class TrayController:
    def __init__(
        self,
        tooltip: str,
        on_show: Callable[[], None],
        on_exit: Callable[[], None],
    ):
        self.tooltip = tooltip
        self.on_show = on_show
        self.on_exit = on_exit
        self._backend: _BaseBackend = self._select_backend()

    def _select_backend(self) -> _BaseBackend:
        if pystray and Image:
            return _PystrayBackend(self.tooltip, self.on_show, self.on_exit)
        if os.name == "nt":
            return _NativeBackend(self.tooltip, self.on_show, self.on_exit)
        return _NullBackend()

    def start(self) -> bool:
        return self._backend.start()

    def stop(self):
        self._backend.stop()

    def show(self):
        self._backend.show()

    def hide(self):
        self._backend.hide()

    def is_available(self) -> bool:
        return self._backend.is_available()
