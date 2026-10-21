"""The window players use. All slow work runs on worker threads; the UI polls their state."""

import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from . import APP_NAME, VERSION
from .config import Config, applog
from .gameproc import GameWatcher, tunnel_apps_running
from .pktmon import cleanup as pktmon_cleanup, pktmon_path
from .recorder import Recorder
from . import tray as traymod
from . import theme
from . import updater as upd
from .uploader import Client, UploadError, read_state

CONSENT = (
    "AoW Capture records the network traffic between Age of Wushu and the official "
    "servers, for analysis by whoever gave you this tool.\n\n"
    "• Only the game's own connections are kept. Everything else your PC sends is "
    "thrown away before anything is saved.\n"
    "• Your MAC address and local IP are replaced in the saved file.\n"
    "• The capture does contain what the game sends and receives: your character, "
    "chat, and the login exchange with the game's login server.\n"
    "• Files are saved in Documents\\AoW Captures. With auto-upload on, they're sent "
    "to the upload server from your invite code when a recording ends.\n\n"
    "Windows' built-in Packet Monitor (pktmon) does the recording, which is why the "
    "tool needs administrator rights.\n\nDo you agree to record?"
)


def fmt_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def fmt_time(s):
    s = int(s)
    return f"{s // 3600:d}:{s % 3600 // 60:02d}:{s % 60:02d}"


class App:
    def __init__(self, root, start_hidden=False, just_updated=False):
        self.root = root
        self.pending_update = None
        self.update_text = None         # "Downloading update … 42%" while one downloads
        self.checkpointing = False
        self.installing_update = False
        self.cfg = Config()
        self.events = queue.Queue()
        self.watcher = GameWatcher(self.cfg.get("process_names", ()), self.cfg.get("game_modules", ()))
        self.recorder = Recorder(self.cfg, self.watcher, log=lambda m: self.events.put(("log", m)))
        self.uploads = queue.Queue()
        self.busy = False           # stopping/processing
        self.game_seen_in_capture = False
        self.game_gone_since = None
        self.closing = False
        self.hidden = False
        self.quitting = False
        self.told_about_tray = False
        self.tray = traymod.Tray(lambda action: self.events.put(("tray", action)))

        hide_at_start = start_hidden or self.cfg.get("start_in_tray")
        if hide_at_start and self.cfg.get("consent_given"):
            root.withdraw()             # no flash of the window before it goes to the tray
        root.title(f"{APP_NAME} {VERSION}")
        self.scale = theme.dpi_scale(root)
        root.minsize(self.px(680), self.px(680))
        root.geometry(f"{self.px(720)}x{self.px(800)}")
        self._build()
        self.refresh_list()

        if not self.cfg.get("consent_given"):
            if not messagebox.askyesno(APP_NAME, CONSENT, parent=root):
                root.destroy()
                return
            self.cfg["consent_given"] = True
            self.cfg.save()
        if not pktmon_path():
            root.deiconify()
            messagebox.showerror(APP_NAME, "Windows Packet Monitor (pktmon) wasn't found.\n"
                                 "Windows 10 version 2004 or newer is required.")

        if self.tray.start():
            self.tray_row.pack(anchor="w", pady=(self.px(4), self.px(0)))
            root.bind("<Unmap>", self._on_unmap)
            traymod.listen_for_show(lambda action: self.events.put(("tray", action)))
            if hide_at_start:
                if just_updated:
                    self.told_about_tray = True  # the "updated" note below is enough
                self.hide_window()
        if not self.hidden and root.state() == "withdrawn":
            root.deiconify()            # no tray after all: show the window

        if just_updated:
            self.status.set(f"Updated to {VERSION}.")
            self.tray.notify(f"{APP_NAME} was updated to {VERSION}"
                             + (" and is still running in the tray." if self.hidden else "."))
        if self.cfg.can_upload:
            threading.Thread(target=self._fetch_name, daemon=True).start()
        threading.Thread(target=self._update_loop, daemon=True).start()
        threading.Thread(target=self._watch_loop, daemon=True).start()
        threading.Thread(target=self._upload_loop, daemon=True).start()
        self.queue_pending_uploads()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(300, self.tick)

    # ------------------------------------------------------------ layout
    def _build(self):
        root = self.root
        self.pal = theme.apply(root)
        outer = ttk.Frame(root, padding=(self.px(16), self.px(12), self.px(16), self.px(0)))
        outer.pack(fill="both", expand=True)

        # Update banner (shown only when an update is waiting)
        self.update_bar = ttk.Frame(outer, style="Banner.TFrame", padding=(self.px(12), self.px(8)))
        self.update_var = tk.StringVar()
        ttk.Label(self.update_bar, textvariable=self.update_var, style="Banner.TLabel").pack(side="left")
        self.update_btn = ttk.Button(self.update_bar, text="Restart and update", style="Accent.TButton",
                                     command=self.install_update)
        self.update_btn.pack(side="right")

        # Header: icon, name, game status, recording pill
        head = ttk.Frame(outer)
        head.pack(fill="x", pady=(self.px(0), self.px(10)))
        self.update_bar_anchor = head
        img = theme.icon_image(self.px(48))
        if img is not None:
            from PIL import ImageTk
            self._head_icon = ImageTk.PhotoImage(img)
            ttk.Label(head, image=self._head_icon).pack(side="left", padx=(self.px(0), self.px(12)))
        titles = ttk.Frame(head)
        titles.pack(side="left", fill="x", expand=True)
        ttk.Label(titles, text=APP_NAME, style="Title.TLabel").pack(anchor="w")
        self.game_var = tk.StringVar(value="Looking for the game…")
        ttk.Label(titles, textvariable=self.game_var, style="Muted.TLabel").pack(anchor="w")
        self.pill = tk.Label(head, text="IDLE", padx=self.px(10), pady=self.px(3), bd=0,
                             font=("Segoe UI", 9, "bold") if os.name == "nt" else ("TkDefaultFont", 9, "bold"))
        self.pill.pack(side="right", anchor="n", pady=(self.px(4), self.px(0)))
        self._set_pill("idle")

        # Recording card
        rec = ttk.LabelFrame(outer, text="Recording", style="Card.TLabelframe", padding=self.px(12))
        rec.pack(fill="x", pady=(self.px(0), self.px(10)))
        top = ttk.Frame(rec)
        top.pack(fill="x")
        self.rec_btn = ttk.Button(top, text="●  Start recording", style="Accent.TButton",
                                  command=self.toggle, width=20)
        self.rec_btn.pack(side="left")
        self.rec_var = tk.StringVar(value="Not recording")
        ttk.Label(top, textvariable=self.rec_var, style="Stats.TLabel").pack(side="left", padx=self.px(14))
        self.auto_rec = tk.BooleanVar(value=self.cfg.get("auto_record", True))
        self.auto_up = tk.BooleanVar(value=self.cfg.get("auto_upload", True))
        opts = ttk.Frame(rec)
        opts.pack(fill="x", pady=(self.px(10), self.px(0)))
        ttk.Checkbutton(opts, text="Record automatically when the game starts", variable=self.auto_rec,
                        command=self._save_toggles).pack(side="left")
        self.autosave = tk.BooleanVar(value=self.cfg.get("autosave", True))
        mins = int(self.cfg.get("autosave_minutes", 10) or 10)
        ttk.Checkbutton(opts, text=f"Save and upload every {mins} min", variable=self.autosave,
                        command=self._save_toggles).pack(side="left", padx=self.px(12))

        mark = ttk.Frame(rec)
        mark.pack(fill="x", pady=(self.px(12), self.px(0)))
        ttk.Label(mark, text="Marker", style="Muted.TLabel").pack(anchor="w")
        row = ttk.Frame(mark)
        row.pack(fill="x", pady=(self.px(2), self.px(0)))
        self.marker = ttk.Entry(row)
        self.marker.pack(side="left", fill="x", expand=True)
        self.marker.bind("<Return>", lambda e: self.add_marker())
        ttk.Button(row, text="Add", command=self.add_marker).pack(side="left", padx=(self.px(8), self.px(0)))
        ttk.Label(mark, text="What are you doing right now? e.g. “opening cultivation”, “duel with X”",
                  style="Muted.TLabel").pack(anchor="w", pady=(self.px(2), self.px(0)))

        ttk.Label(rec, text="Note for this recording", style="Muted.TLabel").pack(anchor="w", pady=(self.px(10), self.px(2)))
        self.note = tk.Text(rec, height=2, wrap="word", relief="flat", borderwidth=1, padx=self.px(8), pady=self.px(6),
                            bg=self.pal["field"], fg=self.pal["field_text"],
                            insertbackground=self.pal["field_text"], highlightthickness=1,
                            highlightbackground=self.pal["border"], highlightcolor=self.pal["accent"],
                            font=("Segoe UI", 10) if os.name == "nt" else None)
        self.note.pack(fill="x")

        # Captures card
        listf = ttk.LabelFrame(outer, text="Saved captures", style="Card.TLabelframe", padding=self.px(12))
        listf.pack(fill="both", expand=True, pady=(self.px(0), self.px(10)))
        up = ttk.Frame(listf)
        up.pack(fill="x", pady=(self.px(0), self.px(8)))
        self.up_var = tk.StringVar()
        ttk.Label(up, textvariable=self.up_var, style="Muted.TLabel").pack(side="left")
        ttk.Button(up, text="Invite code…", command=self.enter_invite).pack(side="right")
        self._update_upload_label()
        cols = ("size", "status")
        tf = ttk.Frame(listf)
        tf.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tf, columns=cols, show="headings tree", height=5)
        self.tree.heading("#0", text="File", anchor="w")
        self.tree.heading("size", text="Size", anchor="e")
        self.tree.heading("status", text="   Status", anchor="w")
        self.tree.column("#0", width=self.px(330))
        self.tree.column("size", width=self.px(90), anchor="e")
        self.tree.column("status", width=self.px(170))
        sb = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        btns = ttk.Frame(listf)
        btns.pack(fill="x", pady=(self.px(8), self.px(0)), side="bottom", before=tf)
        ttk.Button(btns, text="Upload selected", command=self.upload_selected).pack(side="left")
        ttk.Button(btns, text="Open folder", command=self.open_folder).pack(side="left", padx=self.px(6))
        ttk.Button(btns, text="Delete", command=self.delete_selected).pack(side="left")
        ttk.Button(btns, text="Diagnostics…", command=self.diagnostics).pack(side="right")

        # Settings
        sett = ttk.Frame(outer)
        sett.pack(fill="x", pady=(self.px(0), self.px(6)), side="bottom", before=listf)  # keeps its space when short
        self.settings_frame = sett
        self.auto_update = tk.BooleanVar(value=self.cfg.get("auto_update", True))
        opts = ttk.Frame(sett)
        opts.pack(anchor="w")
        ttk.Checkbutton(opts, text="Upload automatically", variable=self.auto_up,
                        command=self._save_toggles).pack(side="left")
        ttk.Checkbutton(opts, text="Install updates automatically", variable=self.auto_update,
                        command=self._save_toggles).pack(side="left", padx=self.px(12))
        self.tray_row = ttk.Frame(sett)
        self.close_to_tray = tk.BooleanVar(value=self.cfg.get("close_to_tray", True))
        self.start_in_tray = tk.BooleanVar(value=self.cfg.get("start_in_tray", False))
        ttk.Checkbutton(self.tray_row, text="Keep running in the tray when closed or minimized",
                        variable=self.close_to_tray, command=self._save_toggles).pack(side="left")
        ttk.Checkbutton(self.tray_row, text="Start hidden in the tray", variable=self.start_in_tray,
                        command=self._save_toggles).pack(side="left", padx=self.px(12))

        ttk.Separator(root).pack(fill="x", side="bottom", before=outer)
        self.status = tk.StringVar()
        self.status_label = ttk.Label(root, textvariable=self.status, style="Status.TLabel", anchor="w")
        self.status_label.pack(fill="x", side="bottom", before=outer)

    # ------------------------------------------------------------ actions
    def _save_toggles(self):
        self.cfg["auto_record"] = self.auto_rec.get()
        self.cfg["auto_upload"] = self.auto_up.get()
        self.cfg["auto_update"] = self.auto_update.get()
        self.cfg["autosave"] = self.autosave.get()
        self.cfg["close_to_tray"] = self.close_to_tray.get()
        self.cfg["start_in_tray"] = self.start_in_tray.get()
        self.cfg.save()

    def _fetch_name(self):
        """Ask the upload server who this invite code belongs to; that name goes on the
        captures. Returns the server's answer (raises UploadError)."""
        info = Client(self.cfg["upload_url"], self.cfg["upload_token"]).ping()
        tester = (info.get("tester") or "").strip()[:32]
        if tester and tester != self.cfg.get("tester_name"):
            self.events.put(("tester", tester))
        return info

    def _set_tester(self, name):
        self.cfg["tester_name"] = name
        self.cfg.save()
        self._update_upload_label()

    def enter_invite(self):
        code = simpledialog.askstring(APP_NAME, "Paste the invite code you were given:", parent=self.root)
        if not code:
            return
        try:
            self.cfg.apply_invite(code)
        except ValueError as e:
            messagebox.showerror(APP_NAME, str(e), parent=self.root)
            return
        self.cfg.save()
        self._update_upload_label("Checking…")

        def check():
            try:
                info = self._fetch_name()
                self.events.put(("upload_label", None))
                self.events.put(("status", f"Connected as {info.get('tester') or '?'}."))
                self.queue_pending_uploads()
            except UploadError as e:
                self.events.put(("upload_label", f"Can't connect: {e}"))
        threading.Thread(target=check, daemon=True).start()

    def _update_upload_label(self, override=None):
        if override:
            self.up_var.set(override)
        elif self.cfg.can_upload:
            host = self.cfg["upload_url"].split("://")[-1].split("/")[0]
            name = self.cfg.capture_name
            self.up_var.set(f"Uploading to {host}" + (f" as {name}" if name else ""))
        else:
            self.up_var.set("No invite code: saved on this PC only.")

    def toggle(self):
        if self.busy:
            return
        if self.recorder.recording:
            self.stop_recording()
        else:
            self.start_recording("manual")

    def start_recording(self, reason):
        if getattr(self, "server_kind", None) == "private":
            self.status.set("The game isn't on the official server; those sessions aren't recorded.")
            applog(f"Not recording ({reason}): not the official server")
            return
        tunnels = tunnel_apps_running()
        if tunnels:
            self.status.set(f"{', '.join(tunnels)} is running: recording the game's link to it on this PC.")
        try:
            self.recorder.start(reason)
        except Exception as e:
            applog(f"Couldn't start recording: {e}")
            self.show_window()
            messagebox.showerror(APP_NAME, f"Couldn't start recording:\n{e}", parent=self.root)
            return
        self.game_seen_in_capture = bool(self.watcher.pids)
        if self.hidden:
            self.tray.notify("Recording started." if reason == "manual" else "The game started: recording.")
        if tunnels and self.recorder.sniffer is None:
            applog(f"{tunnels} running but the loopback capture didn't start")
            self.show_window()
            messagebox.showwarning(APP_NAME, f"{', '.join(tunnels)} is running, but its link can't be "
                                   "recorded on this PC. Quit it fully (not just pause) or the capture "
                                   "will come out empty.", parent=self.root)
        self.game_gone_since = None

    def stop_recording(self, then_exit=False):
        if self.busy or not self.recorder.recording:
            return
        self.busy = True
        note = self.note.get("1.0", "end").strip()

        def work():
            path, err = None, None
            try:
                path = self.recorder.stop(note, progress=lambda s: self.events.put(("status", s)))
            except Exception as e:
                err = e
            self.events.put(("stopped", (path, err, then_exit)))
        threading.Thread(target=work, daemon=True).start()

    def diagnostics(self):
        self.status.set("Collecting diagnostics (a few seconds)…")

        def work():
            from .diagnose import write_and_open
            try:
                path = write_and_open()
                self.events.put(("status", f"Diagnostics saved to {path}. Send that file to whoever gave you the tool."))
            except Exception as e:
                self.events.put(("status", f"Diagnostics failed: {e}"))
        threading.Thread(target=work, daemon=True).start()

    def add_marker(self):
        text = self.marker.get()
        if not self.recorder.recording:
            self.status.set("Markers can only be added while recording.")
            return
        self.recorder.add_marker(text)
        self.marker.delete(0, "end")

    # ------------------------------------------------------------ captures list
    def captures(self):
        d = self.cfg["capture_dir"]
        try:
            names = [n for n in os.listdir(d) if n.endswith(".zip")]
        except OSError:
            return []
        return sorted((os.path.join(d, n) for n in names), key=os.path.getmtime, reverse=True)

    def refresh_list(self):
        self.tree.delete(*self.tree.get_children())
        labels = {"local": "Saved", "pending": "Waiting to upload", "uploading": "Uploading…",
                  "uploaded": "Uploaded ✓"}
        for path in self.captures():
            st = read_state(path)
            label = labels.get(st.get("status"), st.get("status", ""))
            if st.get("progress") and st.get("status") == "uploading":
                label = f"Uploading {st['progress']}%"
            if st.get("error") and st.get("status") == "pending":
                label = "Retrying: " + st["error"][:40]
            self.tree.insert("", "end", iid=path, text=os.path.basename(path),
                             values=(fmt_size(os.path.getsize(path)), label))

    def selected(self):
        return list(self.tree.selection())

    def upload_selected(self):
        if not self.cfg.can_upload:
            self.enter_invite()
            return
        for p in self.selected():
            self.uploads.put(p)

    def delete_selected(self):
        sel = self.selected()
        if not sel or not messagebox.askyesno(APP_NAME, f"Delete {len(sel)} capture(s) from this PC?",
                                              parent=self.root):
            return
        for p in sel:
            for f in (p, p + ".upload.json"):
                try:
                    os.remove(f)
                except OSError:
                    pass
        self.refresh_list()

    def open_folder(self):
        os.makedirs(self.cfg["capture_dir"], exist_ok=True)
        if os.name == "nt":
            os.startfile(self.cfg["capture_dir"])
        else:
            subprocess.Popen(["xdg-open", self.cfg["capture_dir"]])

    def queue_pending_uploads(self):
        if not (self.cfg.can_upload and self.cfg.get("auto_upload")):
            return
        for p in self.captures():
            if read_state(p).get("status") in ("local", "pending", "uploading"):
                self.uploads.put(p)

    # ------------------------------------------------------------ workers
    def _watch_loop(self):
        while not self.closing:
            try:
                pids = self.watcher.refresh()
            except Exception:
                pids = set()
            ident = (None, None)
            if pids:
                try:
                    ident = self.watcher.server_identity(self.cfg.get("official_servers") or (),
                                                         self.cfg.get("private_servers") or ())
                except Exception:
                    pass
            self.events.put(("game", (self.watcher.describe(), ident)))
            if ident[0] == "private":
                if self.recorder.recording:
                    self.recorder.note_server(*ident)  # the recording is discarded when it stops
                    self.game_seen_in_capture = True    # so it still stops when the game closes
                time.sleep(2)
                continue  # never auto-start on a non-official server
            if ident[0] == "official" and self.recorder.recording:
                self.recorder.note_server(*ident)
            if self.busy:
                time.sleep(2)
                continue
            if pids:
                self.game_gone_since = None
                if self.recorder.recording:
                    self.game_seen_in_capture = True
                elif self.cfg.get("auto_record"):
                    self.events.put(("autostart", None))
            elif self.recorder.recording and self.game_seen_in_capture:
                self.game_gone_since = self.game_gone_since or time.time()
                if time.time() - self.game_gone_since > 5:
                    self.game_gone_since = None
                    self.events.put(("autostop", None))
            time.sleep(2)

    def _upload_loop(self):
        while True:
            path = self.uploads.get()
            if not os.path.exists(path) or not self.cfg.can_upload:
                continue
            if read_state(path).get("status") == "uploaded":
                continue
            client = Client(self.cfg["upload_url"], self.cfg["upload_token"])
            from .uploader import write_state

            def prog(done, total, path=path):
                write_state(path, progress=int(done * 100 / max(total, 1)))
                self.events.put(("list", None))
            try:
                self.events.put(("status", f"Uploading {os.path.basename(path)}…"))
                client.upload(path, progress=prog)
                write_state(path, error=None, progress=None)
                self.events.put(("status", f"Uploaded {os.path.basename(path)}."))
            except UploadError as e:
                write_state(path, status="pending", error=str(e))
                self.events.put(("status", f"Upload failed, will retry: {e}"))
                threading.Timer(120, lambda p=path: self.uploads.put(p)).start()
            self.events.put(("list", None))

    # ------------------------------------------------------------ UI loop
    def tick(self):
        try:
            while True:
                kind, val = self.events.get_nowait()
                if kind == "log" or kind == "status":
                    self.status.set(val)
                elif kind == "game":
                    desc, (server_kind, label) = val
                    if (server_kind, label) != getattr(self, "_last_ident", None):
                        self._last_ident = (server_kind, label)
                        applog(f"Game: {desc or 'not running'}; server: {label or 'unknown'} ({server_kind})")
                    self.server_kind = server_kind
                    if not desc:
                        self.game_var.set("Game not running")
                    elif server_kind == "private":
                        self.game_var.set(f"Game running on another server ({label}): not recorded")
                    else:
                        self.game_var.set(f"Game running: {desc}" + (f" - {label}" if label else ""))
                elif kind == "list":
                    self.refresh_list()
                elif kind == "upload_label":
                    self._update_upload_label(val)
                elif kind == "autostart" and not self.recorder.recording and not self.busy:
                    self.start_recording("game started")
                elif kind == "autostop":
                    self.stop_recording()
                elif kind == "stopped":
                    self._on_stopped(*val)
                elif kind == "tray":
                    self._tray_action(val)
                elif kind == "update_ready":
                    self._on_update_ready(val)
                elif kind == "tester":
                    self._set_tester(val)
                elif kind == "update_failed":
                    if self.update_text:   # a download was under way
                        self.update_text = None
                        self.update_bar.pack_forget()
                        self.status.set(f"The update download failed; trying again later. ({val})")
                elif kind == "update_progress":
                    self._on_update_progress(val)
                elif kind == "part_saved":
                    self._on_part_saved(val)
        except queue.Empty:
            pass
        if self.recorder.recording:
            self.rec_var.set(f"● Recording {fmt_time(self.recorder.elapsed())}   "
                             f"{self.recorder.game_connections()} game connection(s)   "
                             f"raw {fmt_size(self.recorder.raw_size())}")
            self.rec_btn.config(text="■  Stop and save")
            self._set_pill("rec")
            self._maybe_autosave()
            limit = self.cfg.get("raw_limit_mb", 4096) * 1024 * 1024
            if self.recorder.raw_size() > 0.85 * limit:
                self.status.set("Raw capture is nearly full; stop and start a new recording soon.")
        elif self.busy:
            self.rec_var.set("Saving…")
            self.rec_btn.config(text="Saving…")
            self._set_pill("busy")
        else:
            self.rec_var.set("Not recording")
            self.rec_btn.config(text="●  Start recording")
            self._set_pill("idle")
            self._maybe_auto_update()
        if self.closing:
            return
        tip = self.rec_var.get().replace("●", "").strip()
        if self.update_text and not self.recorder.recording:
            tip = self.update_text
        self.tray.update(self.recorder.recording, tip)
        if not self.closing:
            self.root.after(500, self.tick)

    def _on_stopped(self, path, err, then_exit):
        self.busy = False
        if (self.recorder.warning or err) and not then_exit:
            self.show_window()
        if self.recorder.warning:
            messagebox.showwarning(APP_NAME, self.recorder.warning, parent=self.root)
        if err:
            messagebox.showerror(APP_NAME, f"Saving the capture failed:\n{err}", parent=self.root)
        elif path:
            self.note.delete("1.0", "end")
            self.status.set(f"Saved {os.path.basename(path)}")
            uploading = self.cfg.can_upload and self.cfg.get("auto_upload")
            if uploading:
                self.uploads.put(path)
            if self.hidden:
                self.tray.notify(f"Saved {os.path.basename(path)}" + (" and uploading it." if uploading else "."))
        elif self.recorder.skipped_private:
            self.status.set("That session wasn't on the official server, so nothing was saved.")
        else:
            self.status.set("Nothing from the game was recorded, so nothing was saved.")
        self.refresh_list()
        if then_exit:
            self._exit()

    def px(self, n):
        """Pixels at 96 DPI -> pixels on this display."""
        return int(round(n * getattr(self, "scale", 1.0)))

    def _set_pill(self, state):
        if getattr(self, "_pill_state", None) == state:
            return
        self._pill_state = state
        p = self.pal
        text, bg, fg = {"idle": ("IDLE", p["idle"], p["idle_text"]),
                        "rec": ("●  RECORDING", p["rec"], p["rec_text"]),
                        "busy": ("SAVING", p["accent"], "#1c1c1c")}[state]
        self.pill.config(text=text, bg=bg, fg=fg)

    # ------------------------------------------------------------ updates
    def _update_loop(self):
        if not upd.is_frozen():
            return  # running from source: nothing to replace
        time.sleep(15)
        checker = upd.Updater(self.cfg.get("update_repo") or upd.DEFAULT_REPO)
        while not self.closing:
            try:
                u = checker.check()
                if u:
                    last = [-1]

                    def prog(done, total, u=u):
                        pct = int(done * 100 / total) if total else -1
                        key = pct if total else done >> 20   # every 1 % (or MB if size unknown)
                        if key != last[0]:
                            last[0] = key
                            self.events.put(("update_progress", (u, done, total)))
                    self.events.put(("update_progress", (u, 0, 0)))
                    checker.download(u, progress=prog)
                    self.events.put(("update_ready", (checker, u)))
                    return
            except upd.UpdateError as e:
                applog(f"Update check failed: {e}")
                self.events.put(("update_failed", str(e)))
            except Exception as e:
                applog(f"Update check error: {e}")
                self.events.put(("update_failed", str(e)))
            for _ in range(6 * 360):  # every 6 hours
                if self.closing:
                    return
                time.sleep(10)

    def _show_update_bar(self, ready):
        if ready:
            self.update_btn.pack(side="right")
        else:
            self.update_btn.pack_forget()
        if not self.update_bar.winfo_ismapped():
            self.update_bar.pack(fill="x", pady=(self.px(0), self.px(10)), before=self.update_bar_anchor)

    def _on_update_progress(self, val):
        u, done, total = val
        if self.pending_update:
            return
        if total:
            text = f"Downloading update {u.label}… {done * 100 // total}%"
        elif done:
            text = f"Downloading update {u.label}… {fmt_size(done)}"
        else:
            text = f"Downloading update {u.label}…"
        self.update_var.set(text)
        self.status.set(text)
        self.update_text = text
        self._show_update_bar(ready=False)

    def _on_update_ready(self, val):
        self.pending_update = val
        self.update_text = None
        u = val[1]
        self.update_var.set(f"Version {u.label} is ready to install.")
        self._show_update_bar(ready=True)
        self.status.set(f"Update {u.label} downloaded.")
        if self.hidden:
            self.tray.notify(f"Update {u.label} downloaded. It installs when you're not playing.")

    def _idle_for_update(self):
        return (not self.recorder.recording and not self.busy and not self.watcher.pids
                and not self.checkpointing and self.uploads.empty())

    # ------------------------------------------------------------ auto-save
    def _maybe_autosave(self):
        if not self.autosave.get() or self.busy or self.checkpointing:
            return
        minutes = max(1, int(self.cfg.get("autosave_minutes", 10) or 10))
        if self.recorder.since_cut() < minutes * 60:
            return
        self.checkpointing = True

        def work():
            path, err = None, None
            try:
                path = self.recorder.checkpoint()
            except Exception as e:
                err = e
            self.events.put(("part_saved", (path, err)))
        threading.Thread(target=work, daemon=True, name="autosave").start()

    def _on_part_saved(self, val):
        path, err = val
        self.checkpointing = False
        if err:
            applog(f"Auto-save failed: {err}")
            self.status.set(f"Auto-save failed (still recording): {err}")
            return
        if path:
            self.status.set(f"Saved {os.path.basename(path)}; still recording.")
            if self.cfg.can_upload and self.cfg.get("auto_upload"):
                self.uploads.put(path)
            self.refresh_list()

    def _maybe_auto_update(self):
        if (self.pending_update and not self.installing_update and self.auto_update.get()
                and self._idle_for_update()):
            self.install_update(auto=True)

    def install_update(self, auto=False):
        if not self.pending_update or self.installing_update:
            return
        if self.recorder.recording or self.busy:
            if not auto:
                messagebox.showinfo(APP_NAME, "Stop the recording first; the update installs "
                                    "right after.", parent=self.root)
            return
        checker, u = self.pending_update
        self.installing_update = True
        try:
            checker.apply(u, hidden=self.hidden)
        except Exception as e:
            self.installing_update = False
            applog(f"Update failed: {e}")
            if not auto:
                messagebox.showerror(APP_NAME, f"The update couldn't be installed:\n{e}", parent=self.root)
            self.pending_update = None
            self.update_bar.pack_forget()
            return
        self.closing = True
        self._exit()

    # ------------------------------------------------------------ tray
    def _tray_action(self, action):
        if action == "show":
            self.show_window()
        elif action == "toggle":
            self.toggle()
        elif action == "folder":
            self.open_folder()
        elif action == "quit":
            self.quit_app()

    def _on_unmap(self, event):
        # Minimize -> tray (only for the main window, and only when the option is on).
        if event.widget is self.root and not self.hidden and self.close_to_tray.get():
            self.root.after(50, lambda: self.root.state() == "iconic" and self.hide_window())

    def hide_window(self):
        if not self.tray.active or self.hidden:
            return
        self.hidden = True
        self.root.withdraw()
        if not self.told_about_tray:
            self.told_about_tray = True
            self.tray.notify("Still running in the tray. Recording starts when the game does. "
                             "Right-click the icon for options.")

    def show_window(self):
        if self.hidden:
            self.hidden = False
            self.root.deiconify()
        if self.root.state() == "iconic":
            self.root.deiconify()
        self.root.lift()
        self.root.attributes("-topmost", True)
        self.root.after(200, lambda: self.root.attributes("-topmost", False))
        try:
            self.root.focus_force()
        except tk.TclError:
            pass

    def quit_app(self):
        self.show_window()
        self.quitting = True
        self.on_close()
        self.quitting = False

    def on_close(self):
        if self.tray.active and self.close_to_tray.get() and not self.quitting:
            self.hide_window()
            return
        if self.busy:
            return
        if self.recorder.recording:
            ans = messagebox.askyesnocancel(APP_NAME, "A recording is running. Save it before closing?",
                                            parent=self.root)
            if ans is None:
                return
            if ans:
                self.stop_recording(then_exit=True)
                return
            self.recorder.abort()
        self._exit()

    def _exit(self):
        self.closing = True
        self.tray.stop()
        pktmon_cleanup()
        self.root.destroy()


# ------------------------------------------------------------------ startup helpers

def is_admin():
    if os.name != "nt":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    import ctypes
    if getattr(sys, "frozen", False):
        exe, params = sys.executable, subprocess.list2cmdline(sys.argv[1:])
    else:
        exe, params = sys.executable, subprocess.list2cmdline(sys.argv)
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1) > 32


_mutex = None


def single_instance():
    global _mutex
    if os.name != "nt":
        return True
    import ctypes
    _mutex = ctypes.windll.kernel32.CreateMutexW(None, False, "Global\\AoWCaptureSingleInstance")
    return ctypes.windll.kernel32.GetLastError() != 183  # ERROR_ALREADY_EXISTS


def main(start_hidden=False, wait_pid=None):
    theme.enable_dpi_awareness()
    if wait_pid:  # started by the updater: let the old copy exit first
        upd.wait_for_pid(wait_pid)
        upd.cleanup_after_update()
    # Already running (maybe hidden in the tray)? Bring it up instead, before asking for admin.
    elif traymod.signal_running_copy():
        return
    if os.name == "nt" and not is_admin():
        if relaunch_as_admin():
            return
        tk.Tk().withdraw()
        messagebox.showerror(APP_NAME, "AoW Capture needs administrator rights to record.")
        return
    if not single_instance():
        if traymod.signal_running_copy():
            return  # the running copy comes out of the tray
        tk.Tk().withdraw()
        messagebox.showinfo(APP_NAME, "AoW Capture is already running (check the tray icons "
                            "next to the clock).")
        return
    root = tk.Tk()
    try:
        App(root, start_hidden=start_hidden, just_updated=bool(wait_pid))
        root.mainloop()
    finally:
        pktmon_cleanup()
