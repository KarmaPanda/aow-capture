# Changelog

## v0.2.0

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
