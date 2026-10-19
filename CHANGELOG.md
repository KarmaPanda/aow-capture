# Changelog

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
- **Official server only:** sessions on any other server (private servers, emulators)
  are never recorded or uploaded; only official game connections are kept.
- **Tray:** closing or minimizing keeps it running in the tray.

## v0.1.0

- First version: records official sessions with Windows' Packet Monitor, keeps only
  the game's traffic, saves a zip with markers and notes, uploads it.
