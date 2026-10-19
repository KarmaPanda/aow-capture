# AoW Capture

Records official **Age of Wushu (Blue Dragon)** sessions so the private-server project can
match the real game, and uploads them to the project.

- Only the game's own connections to the official servers are saved. Everything else on
  the PC is dropped before anything is written, and the player's MAC/local IP are replaced.
- Sessions on any other server (private servers, our emulator) are never recorded.
- Works with ExitLag (records the game's link to ExitLag's local relay).
- Markers and notes, tray icon, resumable uploads, and it **updates itself** from this
  repo's releases.

Players: see [PLAYER_GUIDE.md](PLAYER_GUIDE.md).

## Install (players)

Download **AoWCapture.zip** from the [latest release](../../releases/latest), unzip it
anywhere, run `AoWCapture.exe`, paste the invite code you were given. After that it keeps
itself up to date.

## How updates work

1. Bump `VERSION` in `client/aowcap/__init__.py` and add a `## vX.Y.Z` section to
   `CHANGELOG.md`.
2. Commit, then tag and push:
   ```
   git tag v0.2.1
   git push origin main v0.2.1
   ```
3. The **Release** workflow tests, builds `AoWCapture.exe` (with the icon) on Windows and
   publishes a release with `AoWCapture.exe`, `AoWCapture.zip` and `SHA256SUMS.txt`. It
   refuses to publish if the tag doesn't match `VERSION`.
4. Every installed copy checks `releases/latest` at start and every 6 hours, downloads the
   exe, checks it against `SHA256SUMS.txt`, and swaps itself when nothing is being played,
   recorded or uploaded (or when the player clicks *Restart and update*). The old exe is
   kept as `AoWCapture.old.exe` until the new one has started.

Only full releases count (drafts and pre-releases are ignored), so you can test a build as
a pre-release first.

## Develop

```
python -m pip install -r requirements.txt pytest
python -m pytest -q tests
python client/aow_capture.py          # run from source (Windows, as administrator)
build.bat                             # local exe in dist/
```

| Path | |
|---|---|
| `client/aowcap/` | the app: `app.py` window, `theme.py` look and icon, `recorder.py`, `pktmon.py` (Windows Packet Monitor), `loopcap.py` (ExitLag relay), `pcapng_filter.py` (keep official traffic, anonymize), `gameproc.py` (find the game, which server it's on), `uploader.py`, `updater.py`, `tray.py`, `diagnose.py` |
| `client/defaults.json` | starting settings shipped next to the exe |
| `receiver/` | the upload receiver and server-side decoder (`aow_capture_receiver.py`, `decode_upload.py`) |
| `assets/aowcapture.ico` | app icon |
| `build.py` / `build.bat` | PyInstaller build + zip + checksums |

Command-line options: `--tray`, `--cli`, `--diagnose`, `--invite CODE`, `--upload-pending`,
`--cleanup`.

## Receiver

`receiver/aow_capture_receiver.py` (standard library only) accepts uploads with per-player
invite codes and decodes each one with `decode_upload.py`. Server setup scripts for the
project's own server are kept outside this repo.
