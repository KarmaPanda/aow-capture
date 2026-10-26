# Changelog

## v0.2.7

- **Much smaller raw recordings.** Packet Monitor now records only the official servers'
  address range instead of all of the PC's traffic (everything else was thrown away at
  save anyway). Downloads, streams and other games no longer fill the raw file. If this
  Windows can't filter by address, it records everything as before.
- **Never loses the start of a long session.** Packet Monitor's raw file overwrites its
  oldest packets once full; now, when it reaches 75 % full, a part is saved and uploaded
  right away (recording continues), even with "Save and upload every 10 min" off.

## v0.2.6

- **A client on another server no longer stops the recording.** Each game client is
  checked on its own: Blue Dragon clients are recorded, and a client on any other server
  is ignored. None of its connections are kept (also not through ExitLag's relay), and
  it's left out of the manifest (`ignored_clients` counts it). Before, one such client
  meant nothing was recorded at all.

## v0.2.5

- **Several game clients at once:** each recording now notes which game client (window)
  made which connection (`clients` in manifest.json: process id, window titles, and each
  connection's local port, server and when it was seen), so every client's traffic can be
  told apart when several are recorded together.

## v0.2.4

- **Follows the upload server when its address changes.** When the tool checks in with
  the upload server and the server names a new address, the tool checks that your invite
  code works there and switches to it. No new invite code needed.

## v0.2.3

- Clearer wording in the consent message and status lines: recordings are for whoever
  gave you the tool, and sessions on any non-official server are simply not recorded.

## v0.2.2

- **Stays in the tray after updating.** If it was hidden in the tray when an update
  installed, the new version starts straight in the tray (no window) and just shows a
  "updated" notification.
- **Shows update download progress:** "Downloading update 0.2.x… 42%" in a banner at the
  top, the status bar and the tray tooltip.
- **No name prompt.** Your name now comes with your invite code: the tool asks the upload
  server who the code belongs to. Captures are named `official_<date>_<time>.zip`, plus
  `_<name>` only when you have an invite code. The "Name…" button is gone.

## v0.2.1

- **Sharp on high-DPI displays.** The window is now DPI-aware: at 125/150/200 % scaling
  text, checkboxes, buttons, the icon and spacing are drawn at full resolution instead of
  being stretched (the theme's images and pixel sizes are scaled to match).

## v0.2.0

- **Saves and uploads every 10 minutes** while recording (parts `_part01`, `_part02`, …),
  so a crash or power cut loses at most the last few minutes. Recording carries on while
  each part is saved and uploaded. Untick "Save and upload every 10 min" to save only at
  the end.
- **ExitLag NDIS mode:** when a booster is running, Packet Monitor records every network
  layer, so the game's packets are caught before ExitLag's driver encrypts them (NDIS
  mode). WFP mode keeps working through ExitLag's local relay.
- **Updates itself.** Checks GitHub Releases at start and every 6 hours, downloads and
  verifies the new version (SHA-256), and installs it when you're not playing or
  recording. Untick "Install updates automatically" to install from the banner instead.
- **New look.** Windows 11 style that follows your light/dark setting, with the
  Age of Wushu icon on the window, the taskbar, the exe and the tray.
- **Diagnostics…** button (or `--diagnose`): writes AoWCapture-diagnostics.txt to the
  Desktop for "it isn't capturing" reports. Sessions are also logged to
  `%LOCALAPPDATA%\AoWCapture\aowcap.log`.
- **ExitLag:** finds its relay on any interface and from any program in ExitLag's
  install folder.
- **Official server only:** sessions on any other server
  are never recorded or uploaded; only official game connections are kept.
- **Tray:** closing or minimizing keeps it running in the tray.

## v0.1.0

- First version: records official sessions with Windows' Packet Monitor, keeps only
  the game's traffic, saves a zip with markers and notes, uploads it.
