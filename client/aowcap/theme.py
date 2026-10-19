"""Look and feel: Windows 11 (Sun Valley) theme following the Windows light/dark setting,
the app icon, and a few custom styles. Falls back to plain ttk when sv_ttk is missing."""

import os
import sys

try:
    import sv_ttk
except Exception:  # pragma: no cover
    sv_ttk = None
try:
    import darkdetect
except Exception:  # pragma: no cover
    darkdetect = None

ICON_NAME = "aowcapture.ico"

PALETTE = {
    "light": {"bg": "#fafafa", "card": "#ffffff", "text": "#1c1c1c", "muted": "#5f5f5f",
              "field": "#ffffff", "field_text": "#1c1c1c", "border": "#e5e5e5",
              "rec": "#c42b1c", "rec_text": "#ffffff", "idle": "#e8e8e8", "idle_text": "#3b3b3b",
              "ok": "#0f7b0f", "accent": "#b8860b", "banner": "#fff4ce", "banner_text": "#3b2f00"},
    "dark": {"bg": "#1c1c1c", "card": "#2b2b2b", "text": "#f3f3f3", "muted": "#a8a8a8",
             "field": "#2d2d2d", "field_text": "#f3f3f3", "border": "#3a3a3a",
             "rec": "#ff5f52", "rec_text": "#1c1c1c", "idle": "#3a3a3a", "idle_text": "#e0e0e0",
             "ok": "#6ccb5f", "accent": "#f2b134", "banner": "#433519", "banner_text": "#fce100"},
}


def resource(*parts):
    """Path to a bundled file (PyInstaller) or to the source tree's assets folder."""
    base = getattr(sys, "_MEIPASS", None)
    candidates = []
    if base:
        candidates.append(os.path.join(base, *parts))
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(here, "..", "..", *parts))     # repo: assets/ at the root
    candidates.append(os.path.join(here, "..", *parts))
    for c in candidates:
        if os.path.exists(c):
            return os.path.normpath(c)
    return None


def icon_path():
    return resource("assets", ICON_NAME)


def icon_image(size=64):
    """The app icon as a PIL image (or None)."""
    path = icon_path()
    if not path:
        return None
    try:
        from PIL import Image
        img = Image.open(path)
        sizes = sorted(img.info.get("sizes") or [img.size])
        best = next((s for s in sizes if s[0] >= size), sizes[-1])
        img.size = best
        img.load()
        img = img.convert("RGBA")
        return img.resize((size, size), Image.LANCZOS) if img.size != (size, size) else img
    except Exception:
        return None


def mode():
    try:
        return "dark" if darkdetect and darkdetect.isDark() else "light"
    except Exception:
        return "light"


def apply(root):
    """Applies the theme and window icon; returns the palette dict in use."""
    m = mode()
    if sv_ttk is not None:
        try:
            sv_ttk.set_theme(m, root)
        except Exception:
            m = "light"
    pal = dict(PALETTE[m], mode=m)

    path = icon_path()
    try:
        if path and os.name == "nt":
            root.iconbitmap(default=path)
        else:
            img = icon_image(64)
            if img is not None:
                from PIL import ImageTk
                root._icon_ref = ImageTk.PhotoImage(img)
                root.iconphoto(True, root._icon_ref)
    except Exception:
        pass

    from tkinter import ttk
    st = ttk.Style(root)
    family = "Segoe UI Variable Text" if os.name == "nt" else "TkDefaultFont"
    st.configure("Title.TLabel", font=(family, 15, "bold"))
    st.configure("Muted.TLabel", foreground=pal["muted"])
    st.configure("Stats.TLabel", font=(family, 10), foreground=pal["muted"])
    st.configure("Card.TLabelframe.Label", font=(family, 10, "bold"))
    st.configure("PillIdle.TLabel", background=pal["idle"], foreground=pal["idle_text"],
                 padding=(10, 3), font=(family, 9, "bold"))
    st.configure("PillRec.TLabel", background=pal["rec"], foreground=pal["rec_text"],
                 padding=(10, 3), font=(family, 9, "bold"))
    st.configure("PillBusy.TLabel", background=pal["accent"], foreground="#1c1c1c",
                 padding=(10, 3), font=(family, 9, "bold"))
    st.configure("Banner.TFrame", background=pal["banner"])
    st.configure("Banner.TLabel", background=pal["banner"], foreground=pal["banner_text"])
    st.configure("Status.TLabel", foreground=pal["muted"], padding=(12, 4))
    st.configure("Treeview", rowheight=26)
    return pal
