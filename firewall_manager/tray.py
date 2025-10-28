import threading
from typing import Callable, Optional

try:
    import pystray
    from PIL import Image, ImageDraw
except Exception:  # pragma: no cover - optional dependency
    pystray = None
    Image = None
    ImageDraw = None


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
        self._icon: Optional[pystray.Icon] = None if pystray else None
        self._thread: Optional[threading.Thread] = None
        self._visible = False

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
        self._visible = True
        return True

    def stop(self):
        if not self._icon:
            return
        try:
            self._icon.stop()
        except Exception:
            pass
        self._icon = None
        self._visible = False

    def show(self):
        if self._icon:
            self._icon.visible = True
            self._visible = True

    def hide(self):
        if self._icon:
            self._icon.visible = False
            self._visible = False

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
