VAULT-OS - private file server + security dashboard (Python 3.8+, nothing to install)
RUN:  python3 app.py   (or start.bat / start.sh)   ->  http://127.0.0.1:8443
On first launch, create the Commander account (password of 10+ characters).

Optional env vars:
  HOST=0.0.0.0 PORT=8443        (enable HTTPS before exposing it to a network)
  CERT=cert.pem KEY=key.pem     (HTTPS)  -> openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj /CN=vault
  TG_TOKEN=... TG_CHAT=...      (Telegram bot notifications on your phone)
Files are saved in the ./vault/ folder. Data/logs: data.db
The Run button (Python/C++/JS) executes code on the server - use it only with a trusted login and keep HOST=127.0.0.1.

--- Visitors + Friday tab ---
* Every IP that hits the server (even before login) is logged: city/country/ISP, VPN/hosting flag, suspicious paths (.env, wp-login...) and flood detection.
* A crit alert (+Telegram) is raised for an unknown IP (one that has never logged in). Block / Allow buttons are available; a blocked IP gets a 403.
  For a hard block, also use the firewall:  sudo ufw deny from <ip>
* Behind a Cloudflare tunnel, the real IP is taken from CF-Connecting-IP.
* On the first run, 3 websites (page-change alerts) and 5 Instagram accounts (uptime) are added to Monitors. Instagram blocks bots -> shown as LIMITED, no alert.
* Friday summary (the AI assistant): set ANTHROPIC_API_KEY (optional CLAUDE_MODEL), otherwise a local summary is used.
* IP location is approximate. Before exposing this to the public internet, HTTPS and a strong password are mandatory; the Run button executes code on the server.

--- Tracker tab (UOBI Tracker Grid merged) ---
* After login, the "Tracker" tab shows a satellite map + operatives list. The callsign is your login username (set by the server, cannot be changed).
* Location sharing starts automatically on login (the browser/site must have Location permission set to Allow). There is no button.
* You leave the map when you log out. Locations older than 24 hours are deleted automatically. Only logged-in users can see the map.
* Location needs HTTPS or localhost (CERT/KEY or a cloudflared tunnel). The map needs internet (Leaflet cdnjs + Esri tiles).

--- Friday voice assistant ---
* Tap the "Friday: OFF" button (top bar) once and allow the microphone. Friday then listens continuously and answers out loud.
* Say: "Friday, show summary" -> opens Visitors + Friday and reads the summary aloud.
        "Friday, play music"  -> plays every .mp3 in the vault (any sub-folder), one after another.
        "Friday, play <song name>" -> starts that file.   "Friday, next"   "Friday, stop"
* Needs Chrome, Edge or Safari, internet (speech recognition is done by the browser vendor) and HTTPS or localhost for the microphone.
* Multiple devices: you can stay logged in on several devices at once; logging out on one device no longer logs out the others.
