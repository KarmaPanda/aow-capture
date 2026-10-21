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


# ------------------------------------------------------------------ high DPI

def enable_dpi_awareness():
    """Call before the first Tk window. Without it Windows renders the app at 96 DPI and
    stretches the bitmap (blurry on 150%/200% displays). System-aware rather than
    per-monitor: Tk doesn't re-layout when moved between monitors with different scaling."""
    if os.name != "nt":
        return
    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)   # PROCESS_SYSTEM_DPI_AWARE
        except (AttributeError, OSError):
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def dpi_scale(root):
    """1.0 at 96 DPI, 1.5 at 150 %, 2.0 at 200 %."""
    try:
        return max(1.0, round(root.winfo_fpixels("1i") / 96.0, 2))
    except Exception:
        return 1.0


def _scaled_sv_ttk(scale):
    """A copy of the sv_ttk theme with its images, element sizes and pixel fonts scaled.
    sv_ttk draws everything from a 1x sprite sheet with pixel sizes, which would look tiny
    (or blurry if stretched) on a scaled display. Cached per scale factor."""
    import re
    import shutil
    from PIL import Image
    from .config import app_dir
    src = os.path.dirname(sv_ttk.__file__)
    ver = getattr(sv_ttk, "__version__", "") or str(int(os.path.getmtime(os.path.join(src, "sv.tcl"))))
    dst = os.path.join(app_dir(), "theme-cache", f"sv_ttk-{ver}-{scale:.2f}")
    done = os.path.join(dst, ".done")
    if os.path.exists(done):
        return os.path.join(dst, "sv.tcl")
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.py", "*.pyc"))

    def sc(n):
        return str(max(1, int(round(int(n) * scale)))) if int(n) else "0"

    # pixel fonts:  font create X -family "..." -size -14
    p = os.path.join(dst, "sv.tcl")
    t = open(p, encoding="utf-8").read()
    t = re.sub(r"(-size\s+)-(\d+)", lambda m: f"{m.group(1)}-{sc(m.group(2))}", t)
    open(p, "w", encoding="utf-8").write(t)

    for theme in ("light", "dark"):
        sheet = os.path.join(dst, "theme", f"spritesheet_{theme}.png")
        img = Image.open(sheet)
        img.resize((round(img.width * scale), round(img.height * scale)), Image.LANCZOS).save(sheet)
        # sprite rectangles: name x y w h  (scale edges so neighbours stay aligned)
        sp = os.path.join(dst, "theme", f"sprites_{theme}.tcl")
        t = open(sp, encoding="utf-8").read()

        def rect(m):
            x, y, w, h = (int(v) for v in m.group(2, 3, 4, 5))
            x2, y2 = round((x + w) * scale), round((y + h) * scale)
            x1, y1 = round(x * scale), round(y * scale)
            return f"{m.group(1)} {x1} {y1} {x2 - x1} {y2 - y1}"
        t = re.sub(r"(^\s*[\w-]+) (\d+) (\d+) (\d+) (\d+)", rect, t, flags=re.M)
        open(sp, "w", encoding="utf-8").write(t)
        # element/style sizes in pixels
        tp = os.path.join(dst, "theme", f"{theme}.tcl")
        t = open(tp, encoding="utf-8").read()
        t = re.sub(r"(-(?:border|padding|width|height|expand|sashthickness)\s+)(\{[0-9 ]+\}|\d+)",
                   lambda m: m.group(1) + re.sub(r"\d+", lambda d: sc(d.group(0)), m.group(2)), t)
        open(tp, "w", encoding="utf-8").write(t)
    open(done, "w").close()
    return os.path.join(dst, "sv.tcl")


def mode():
    try:
        return "dark" if darkdetect and darkdetect.isDark() else "light"
    except Exception:
        return "light"


def apply(root):
    """Applies the theme and window icon; returns the palette dict in use."""
    m = mode()
    scale = dpi_scale(root)
    if sv_ttk is not None:
        try:
            if scale > 1.05:
                from tkinter import ttk as _ttk
                st0 = _ttk.Style(root)
                st0.tk.call("source", _scaled_sv_ttk(scale))
                root._sv_ttk_loaded = True
                st0.theme_use(f"sun-valley-{m}")
            else:
                sv_ttk.set_theme(m, root)
        except Exception:
            try:
                sv_ttk.set_theme(m, root)
            except Exception:
                m = "light"
    pal = dict(PALETTE[m], mode=m, scale=scale)

    def px(n):
        return int(round(n * scale))

    path = icon_path()
    try:
        if path and os.name == "nt":
            root.iconbitmap(default=path)
        else:
            img = icon_image(px(64))
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
                 padding=(px(10), px(3)), font=(family, 9, "bold"))
    st.configure("PillRec.TLabel", background=pal["rec"], foreground=pal["rec_text"],
                 padding=(px(10), px(3)), font=(family, 9, "bold"))
    st.configure("PillBusy.TLabel", background=pal["accent"], foreground="#1c1c1c",
                 padding=(px(10), px(3)), font=(family, 9, "bold"))
    st.configure("Banner.TFrame", background=pal["banner"])
    st.configure("Banner.TLabel", background=pal["banner"], foreground=pal["banner_text"])
    st.configure("Status.TLabel", foreground=pal["muted"], padding=(px(12), px(4)))
    st.configure("Treeview", rowheight=px(26))
    return pal
