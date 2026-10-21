"""Builds dist/AoWCapture.exe and the release files (Windows, Python 3.10+).

    python -m pip install -r requirements.txt pyinstaller
    python build.py

Output in dist/:
    AoWCapture.exe        one-file build with the app icon, asks for admin on start
    defaults.json         starting settings for players (edit before handing out)
    README.txt            the player guide
    AoWCapture.zip        the three files above, for first-time installs
    SHA256SUMS.txt        checksums; the built-in updater verifies AoWCapture.exe against it
"""

import hashlib
import os
import shutil
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(ROOT, "dist")
SEP = ";" if os.name == "nt" else ":"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main():
    icon = os.path.join(ROOT, "assets", "aowcapture.ico")
    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--windowed",
           "--uac-admin", "--name", "AoWCapture", "--icon", icon,
           "--paths", os.path.join(ROOT, "client"),
           "--hidden-import", "pystray._win32",
           "--collect-data", "sv_ttk",
           "--add-data", f"{icon}{SEP}assets",
           "--add-data", f"{os.path.join(ROOT, 'client', 'defaults.json')}{SEP}.",
           "--distpath", DIST, "--workpath", os.path.join(ROOT, "build"), "--specpath", os.path.join(ROOT, "build"),
           os.path.join(ROOT, "client", "aow_capture.py")]
    subprocess.check_call(cmd)

    shutil.copy(os.path.join(ROOT, "client", "defaults.json"), os.path.join(DIST, "defaults.json"))
    shutil.copy(os.path.join(ROOT, "PLAYER_GUIDE.md"), os.path.join(DIST, "README.txt"))
    exe = os.path.join(DIST, "AoWCapture.exe")
    zpath = os.path.join(DIST, "AoWCapture.zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for name in ("AoWCapture.exe", "defaults.json", "README.txt"):
            z.write(os.path.join(DIST, name), name)
    with open(os.path.join(DIST, "SHA256SUMS.txt"), "w", newline="\n") as f:
        for name in ("AoWCapture.exe", "AoWCapture.zip"):
            f.write(f"{sha256(os.path.join(DIST, name))}  {name}\n")
    print("Built", exe)


if __name__ == "__main__":
    main()
