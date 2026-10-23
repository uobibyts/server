# VAULT-OS (GitHub Pages edition)

Static version of VAULT-OS: no server, everything runs in your browser.

## Deploy
1. Push this folder to a GitHub repo.
2. Settings -> Pages -> Source: `main` branch, `/ (root)` -> Save.
3. Open `https://<username>.github.io/<repo>/`

## Built-in browser (Browser tab)
Proxy / Reader modes use public CORS proxies (they can see the URLs you open). Direct mode is private but many sites refuse embedding. Do not log in to accounts inside it.

## How it works here
- Files (Vault tab) are stored in your browser's IndexedDB; alerts/logins/blocklist in localStorage. Data stays per browser/device (no sync).
- First visit: create the Commander account (password 10+ chars). It is only a local lock on that browser, NOT real security, because the code is public. Never store real secrets in the vault.
- Run button: JavaScript (sandboxed) and Python (Pyodide, downloads ~10 MB on first run). C/C++ is not available.
- Threat Scan works fully offline. Monitors only test reachability (no page-change detection).
- Visitors tab shows only this browser. Tracker shows only your own location (needs HTTPS - Pages provides it).
- Friday voice works (Chrome/Edge/Safari). Summary is local (no AI key in public code).

`server-version/` holds the original Python server (needs a real host). Delete it if unused.
