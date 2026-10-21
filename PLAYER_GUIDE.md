AoW Capture — player guide
==========================

Thanks for helping! This tool records the traffic between Age of Wushu and the
official servers so it can be studied.

What it keeps
-------------
- Only the game's own connections. Everything else on your PC (browser,
  Discord, other games) is thrown away before anything is saved.
- Your MAC address and local IP are replaced in the saved file.
- It does contain what the game sends and receives: your character, chat and
  the login exchange with the game's login server.

Setup (once)
------------
1. Download AoWCapture.zip from
   https://github.com/KarmaPanda/aow-capture/releases/latest, unzip it
   anywhere (not inside Program Files) and run AoWCapture.exe. Windows asks for
   administrator rights: the recording uses Windows' own Packet Monitor
   (pktmon), which needs them. Nothing else is installed.
   Windows 10 version 2004 (May 2020) or newer is required.
2. Read and accept the consent message.
3. Click "Invite code…" and paste the code you were sent. The bar should say
   "Uploading to … as <your name>" (the name comes with your invite code).

Before you play
---------------
- ExitLag is fine, in either redirection mode (WFP or NDIS): the tool records
  the game's traffic before ExitLag encrypts it. Windows may ask whether to allow
  AoWCapture through the firewall the first time; allow it.
- Other VPNs or game boosters: if the tool warns after saving that the game's
  connections "carried almost no data", quit the VPN/booster completely (not
  just pause) and record again.

Only the official server is recorded
------------------------------------
- The tool only records sessions on the official Blue Dragon server. If the
  game is connected to any other server, it doesn't record, and nothing from that session is saved or uploaded.

Recording
---------
- Leave AoW Capture open and start the game. With "Record automatically when
  the game starts" ticked, recording starts by itself and stops ~5 seconds
  after the game closes.
- Or press "Start recording" before launching and "Stop and save" when done.
- While playing, type what you're doing into the Marker box and press Enter
  ("opening cultivation", "duel with X", "buying from gold shop"). Markers
  are timestamped and make the capture far more useful.
- Add a note before stopping if something interesting happened.
- While recording, everything captured so far is saved and uploaded every 10
  minutes (as _part01, _part02, ...), so a crash or power cut only loses the
  last few minutes. Recording keeps going while each part is saved.

Running in the tray
-------------------
- Closing or minimizing the window keeps AoW Capture running as an icon in
  the tray, next to the clock (you may need to click the ^ arrow to see it).
  It keeps recording and uploading from there.
- The icon is red while recording. Double-click it to open the window;
  right-click for Start/Stop recording, Open captures folder and Quit.
- Starting AoWCapture.exe again while it's in the tray opens the window.
- Untick "Keep running in the tray when closed or minimized" to make closing
  the window quit the tool. Tick "Start hidden in the tray" to have it start
  straight into the tray.
- To quit, right-click the tray icon > Quit.

Updates
-------
- AoW Capture updates itself. When a new version is out it downloads it in
  the background and installs it the next time you're not playing or
  recording; a yellow bar shows when one is waiting. Click "Restart and
  update" to install it right away.
- Untick "Install updates automatically" to only install from that bar.

After recording
---------------
- Saved captures are in Documents\AoW Captures as
  official_<date>_<time>_<name>.zip (without an invite code, just
  official_<date>_<time>.zip).
- With "Upload automatically" on, they're sent right away. If the upload
  fails (no internet, PC asleep), it retries and resumes where it stopped,
  including the next time you open the tool.
- No invite code? Send the .zip files by hand (Discord, Drive…).

Problems
--------
- "Nothing from the game was recorded": the game wasn't running, or a
  VPN/booster the tool can't see through was on.
- Not capturing (with ExitLag or otherwise)? Start the game and log in the way
  you normally play, then click "Diagnostics..." in the AoW Capture window (or
  run AoWCapture.exe --diagnose). It saves AoWCapture-diagnostics.txt on your
  Desktop; send that file. It contains no passwords or invite codes.
- Recording seems stuck after a crash: run AoWCapture.exe again (it clears
  the old session), or in an admin command prompt run: pktmon stop
