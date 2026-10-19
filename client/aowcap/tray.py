"""System-tray icon for AoW Capture (Windows notification area).

The icon runs on its own thread (pystray). Its menu actions never touch Tk directly;
they go through the app's event queue, which the Tk loop drains in App.tick().
If pystray / Pillow are missing or the platform has no tray, everything here is a
no-op and the app behaves as before (closing the window quits).
"""

import os
import threading

from . import APP_NAME

try:  # pystray can raise non-ImportErrors at import time (e.g. no display on Linux)
    import pystray
    from PIL import Image, ImageDraw
    _AVAILABLE = True
except Exception:  # pragma: no cover - depends on the platform
    pystray = Image = ImageDraw = None
    _AVAILABLE = False


def available():
    return _AVAILABLE


def make_icon(recording):
    """64x64 tray icon: the app icon, with a red dot in the corner while recording."""
    try:
        from .theme import icon_image
        base = icon_image(64)
    except Exception:
        base = None
    if base is None:  # fallback drawing
        base = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        d = ImageDraw.Draw(base)
        d.ellipse((4, 4, 60, 60), fill=(32, 36, 44, 255), outline=(220, 224, 230, 255), width=4)
        d.ellipse((20, 20, 44, 44), fill=(40, 170, 160, 255))
    img = base.copy()
    if recording:
        d = ImageDraw.Draw(img)
        d.ellipse((36, 36, 63, 63), fill=(255, 255, 255, 255))
        d.ellipse((40, 40, 59, 59), fill=(225, 35, 35, 255))
    return img


class Tray:
    def __init__(self, post):
        """post(action) queues an action string for the Tk thread."""
        self.post = post
        self.icon = None
        self.recording = False
        self._images = {}

    @property
    def active(self):
        return self.icon is not None

    def _image(self, recording):
        if recording not in self._images:
            self._images[recording] = make_icon(recording)
        return self._images[recording]

    def start(self):
        if not _AVAILABLE or self.icon is not None:
            return False
        item = pystray.MenuItem
        menu = pystray.Menu(
            item("Show AoW Capture", lambda: self.post("show"), default=True),
            item(lambda _: "Stop and save recording" if self.recording else "Start recording",
                 lambda: self.post("toggle")),
            item("Open captures folder", lambda: self.post("folder")),
            pystray.Menu.SEPARATOR,
            item("Quit", lambda: self.post("quit")),
        )
        try:
            self.icon = pystray.Icon("AoWCapture", self._image(False), APP_NAME, menu)
            threading.Thread(target=self.icon.run, daemon=True, name="tray").start()
        except Exception:
            self.icon = None
            return False
        return True

    def update(self, recording, tooltip):
        if not self.icon:
            return
        if recording != self.recording:
            self.recording = recording
            try:
                self.icon.icon = self._image(recording)
                self.icon.update_menu()
            except Exception:
                pass
        tip = f"{APP_NAME}: {tooltip}"[:120]  # Windows limits tooltips to 127 chars
        try:
            if self.icon.title != tip:
                self.icon.title = tip
        except Exception:
            pass

    def notify(self, message, title=APP_NAME):
        if not self.icon:
            return
        try:
            self.icon.notify(message[:250], title)
        except Exception:
            pass

    def stop(self):
        if self.icon:
            try:
                self.icon.stop()
            except Exception:
                pass
            self.icon = None


# ------------------------------------------------------------------ "show the running copy"
# A second launch can't open a second window (single instance), so it signals the running
# copy to come out of the tray instead, through a named Win32 event.

_SHOW_EVENT = "Local\\AoWCaptureShowWindow"
# Anyone in the session may signal it, including a not-yet-elevated second launch
# (the running copy is elevated, so the event also gets a low integrity label).
_SHOW_EVENT_SDDL = "D:(A;;0x1F0003;;;WD)S:(ML;;NW;;;LW)"


def _k32():
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateEventW.restype = wintypes.HANDLE
    k32.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
    k32.OpenEventW.restype = wintypes.HANDLE
    k32.OpenEventW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    k32.SetEvent.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k32.WaitForSingleObject.restype = wintypes.DWORD
    return k32


def listen_for_show(post):
    """In the running copy: wait for the event and ask the UI to show itself."""
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes
    k32 = _k32()

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", wintypes.BOOL)]
    sa_ptr = None
    sd = ctypes.c_void_p()
    try:
        adv = ctypes.WinDLL("advapi32", use_last_error=True)
        if adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                ctypes.c_wchar_p(_SHOW_EVENT_SDDL), 1, ctypes.byref(sd), None):
            sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), sd, False)
            sa_ptr = ctypes.byref(sa)
    except (OSError, AttributeError):
        pass
    handle = k32.CreateEventW(sa_ptr, False, False, _SHOW_EVENT)  # auto-reset
    if not handle:
        return

    def loop():
        while True:
            if k32.WaitForSingleObject(handle, 0xFFFFFFFF) == 0:
                post("show")
    threading.Thread(target=loop, daemon=True, name="show-listener").start()


def signal_running_copy():
    """In a second launch: ask the running copy to show its window. True if signalled."""
    if os.name != "nt":
        return False
    try:
        k32 = _k32()
        handle = k32.OpenEventW(0x0002, False, _SHOW_EVENT)  # EVENT_MODIFY_STATE
    except OSError:
        return False
    if not handle:
        return False
    ok = bool(k32.SetEvent(handle))
    k32.CloseHandle(handle)
    return ok
