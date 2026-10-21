"""AoW Capture entry point.

    aow_capture.exe                 window (default)
    aow_capture.exe --tray          start hidden in the tray (e.g. from a startup shortcut)
    aow_capture.exe --cli           record in a console until Enter is pressed
    aow_capture.exe --upload-pending
    aow_capture.exe --invite CODE   store an invite code
    aow_capture.exe --cleanup       stop a stuck pktmon session
    aow_capture.exe --diagnose      write AoWCapture-diagnostics.txt to the Desktop
"""

import argparse
import os
import sys

from aowcap import APP_NAME, VERSION


def cli_record(cfg):
    import threading
    import time
    from aowcap.gameproc import GameWatcher
    from aowcap.recorder import Recorder
    from aowcap.uploader import Client, UploadError

    watcher = GameWatcher(cfg.get("process_names", ()), cfg.get("game_modules", ()))
    stop = threading.Event()

    def watch():
        while not stop.is_set():
            watcher.refresh()
            time.sleep(2)
    threading.Thread(target=watch, daemon=True).start()
    rec = Recorder(cfg, watcher)
    rec.start("cli")
    print("Recording. Type a marker and press Enter to add it; an empty line stops.")
    try:
        while True:
            line = input("> ")
            if not line.strip():
                break
            rec.add_marker(line)
    except (KeyboardInterrupt, EOFError):
        pass
    note = input("Note for this capture (optional): ") if sys.stdin.isatty() else ""
    path = rec.stop(note, progress=print)
    stop.set()
    if path:
        print("Saved", path)
        if cfg.can_upload and cfg.get("auto_upload"):
            try:
                Client(cfg["upload_url"], cfg["upload_token"]).upload(path, progress=lambda d, t: print(f"  {d * 100 // t}%"))
                print("Uploaded.")
            except UploadError as e:
                print("Upload failed (will retry next time):", e)


def upload_pending(cfg):
    from aowcap.uploader import Client, UploadError, read_state
    if not cfg.can_upload:
        print("No invite code stored.")
        return 1
    client = Client(cfg["upload_url"], cfg["upload_token"])
    d = cfg["capture_dir"]
    for name in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        path = os.path.join(d, name)
        if name.endswith(".zip") and read_state(path).get("status") != "uploaded":
            try:
                client.upload(path)
                print("Uploaded", name)
            except UploadError as e:
                print("Failed", name, e)
    return 0


def main():
    ap = argparse.ArgumentParser(prog="aow_capture", description=f"{APP_NAME} {VERSION}")
    ap.add_argument("--cli", action="store_true")
    ap.add_argument("--upload-pending", action="store_true")
    ap.add_argument("--invite")
    ap.add_argument("--cleanup", action="store_true")
    ap.add_argument("--tray", action="store_true", help="start hidden in the tray")
    ap.add_argument("--diagnose", action="store_true", help="write a diagnostics report")
    ap.add_argument("--wait-pid", type=int, help=argparse.SUPPRESS)  # used by the updater
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args()

    if args.diagnose:
        from aowcap.diagnose import write_and_open
        print(write_and_open())
        return 0
    if not (args.cli or args.upload_pending or args.invite or args.cleanup):
        from aowcap.app import main as gui_main
        gui_main(start_hidden=args.tray, wait_pid=args.wait_pid)
        return 0

    from aowcap.config import Config
    cfg = Config()
    if args.invite:
        info = cfg.apply_invite(args.invite)
        cfg.save()
        try:
            from aowcap.uploader import Client
            tester = Client(cfg["upload_url"], cfg["upload_token"]).ping().get("tester")
            if tester:
                cfg["tester_name"] = tester
                cfg.save()
        except Exception as e:
            print(f"Couldn't reach the upload server yet: {e}")
        print(f"Invite stored: {info['url']} as {cfg.get('tester_name') or '?'}")
    if args.cleanup:
        from aowcap.pktmon import cleanup
        cleanup()
        print("pktmon stopped and filters cleared.")
    if args.upload_pending:
        return upload_pending(cfg)
    if args.cli:
        cli_record(cfg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
