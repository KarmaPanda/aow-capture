# AoW Capture

A Windows tool that records **Age of Wushu (Blue Dragon)** game sessions — the network
traffic between the game and the official servers — and optionally uploads each recording
to a server you were given an invite code for.

- **Only the game's own traffic.** Only the game's connections to the official servers are
  saved; everything else on the PC (browser, Discord, other games) is dropped before anything
  is written. The PC's MAC address and local IP are replaced in the saved file.
- **Official server only.** Sessions on any other server are never recorded or uploaded.
- **Works with ExitLag** in both modes: WFP (the game talks to ExitLag's relay on 127.0.0.1,
  recorded with a raw socket) and NDIS (Packet Monitor records every network layer, so the
  game's packets are caught above ExitLag's driver).
- **Nothing lost on a crash.** While recording, a part is saved (and uploaded) every
  10 minutes without stopping the recording.
- Markers and notes, tray icon, resumable uploads, and it **updates itself** from this repo's
  releases.

Recording uses Windows' built-in Packet Monitor (`pktmon`, Windows 10 2004 or newer), which
is why the tool runs as administrator. Nothing else is installed.

Players: see [PLAYER_GUIDE.md](PLAYER_GUIDE.md).

## Install

Download **AoWCapture.zip** from the [latest release](../../releases/latest), unzip it
anywhere, and run `AoWCapture.exe`. If you were given an invite code, click
*Invite code…* and paste it; without one, recordings are only saved on your PC
(`Documents\AoW Captures`). The tool keeps itself up to date.

## What a recording contains

Each recording is a zip, `official_<date>_<time>.zip` (with an invite code,
`official_<date>_<time>_<name>.zip`, the name coming from the upload server):

- a `.pcapng` with only the game's packets (opens in Wireshark),
- `manifest.json`: tool and game version, start/end, server endpoints, markers, note,
  part number for long sessions.

The capture does contain what the game itself sends and receives, including your
character, chat and the login exchange, so only share recordings with people you trust.

## How updates work

1. Bump `VERSION` in `client/aowcap/__init__.py` and add a `## vX.Y.Z` section to
   `CHANGELOG.md`.
2. Commit and push to `main`. No tag needed.
3. The **Release** workflow sees that `vX.Y.Z` hasn't been released yet, tests, builds
   `AoWCapture.exe` on Windows and publishes release `vX.Y.Z` with `AoWCapture.exe`,
   `AoWCapture.zip` and `SHA256SUMS.txt`. Pushes that don't change `VERSION` release
   nothing.
4. Installed copies check `releases/latest` at start and every 6 hours, download the exe,
   verify it against `SHA256SUMS.txt`, and swap themselves when nothing is being played,
   recorded or uploaded (or when the player clicks *Restart and update*). The old exe is
   kept as `AoWCapture.old.exe` until the new one has started.

Only full releases count (drafts and pre-releases are ignored).

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
| `tests/` | tests; `fake_receiver.py` implements the upload API for them |
| `assets/aowcapture.ico` | app icon |
| `build.py` / `build.bat` | PyInstaller build + zip + checksums |

Command-line options: `--tray`, `--cli`, `--diagnose`, `--invite CODE`, `--upload-pending`,
`--cleanup`.

## Upload API

The upload server isn't part of this repo. An invite code (`AOWCAP1.…`) carries its URL and
a per-player token, sent as `Authorization: Bearer <token>`:

| | |
|---|---|
| `GET /api/v1/ping` | `{"ok", "tester", "max_bytes"}`; captures are named after `tester` |
| `POST /api/v1/uploads` `{filename, size, sha256}` | `{"id", "offset", "done"}`; a file already received answers `done` |
| `PUT /api/v1/uploads/<id>?offset=N` | one chunk (4 MB); `409 {"offset"}` means resume from there |

See `tests/fake_receiver.py` for a minimal implementation.
