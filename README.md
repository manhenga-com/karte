# Karte RouterOS Management System - Flask

Simple Flask app for managing MikroTik RouterOS routers, access users, setup scripts, and voucher workflows from a local machine or VPS.

## Folder Structure

```text
mikrotik-hotspot-vouchers-flask/
  app.py
  .env
  requirements.txt
  requirements-vps.txt
  wsgi.py
  deploy/
    ubuntu/
      README.md
      install.sh
      karte-routeros.service
      karte-routeros-sync.service
      karte-routeros-sync.timer
      nginx.conf
  templates/
    base.html
    home.html
    print.html
    profiles.html
    router_form.html
    router_setup_script.html
    routers.html
    settings.html
    voucher_form.html
    vouchers.html
  static/
    app.css
    icon.svg
    mikrotik-logo.svg
    mikrotik-symbol.svg
    manifest.json
    service-worker.js
    vendor/
      bootstrap.min.css
  setup/
    choose-port.ps1
    create-shortcuts.ps1
    disable-autostart.ps1
    enable-autostart.ps1
    mysql-setup.sql
    README-INSTALL.txt
    start-flask-server.bat
  storage/
    database.sqlite
```

By default, `storage/database.sqlite` is created automatically the first time the app runs. For VPS hosting, use MySQL with Gunicorn and Nginx.

## Requirements

- Windows
- Python 3.10 or newer
- MikroTik RouterOS API enabled on the router

Enable the MikroTik API in WinBox under **IP > Services > api**, or run this on the router:

```routeros
/ip service enable api
```

Default plain API port: `8728`.

## Simple Windows Install

For normal use, you only need this:

1. Install Python 3 from `https://www.python.org/downloads/`.
2. During Python installation, tick **Add python.exe to PATH**.
3. Double-click:

```text
INSTALL.bat
```

The installer creates:

- A local `venv` folder for the app
- All Python requirements
- A Desktop shortcut
- A Start Menu shortcut
- An auto-start shortcut so the local server starts after Windows sign-in

After that, open the app using the Desktop shortcut, Start Menu shortcut, or:

```text
START_APP.bat
```

The launcher starts the local Flask server and opens:

```text
http://127.0.0.1:8008
```

If port `8008` is already occupied by an old app process, the launcher automatically uses the next free port.

## Auto-Start

The installer enables auto-start automatically.

To enable it manually, double-click:

```text
ENABLE_AUTOSTART.bat
```

To turn it off, double-click:

```text
DISABLE_AUTOSTART.bat
```

Auto-start begins after Windows sign-in. It starts the local server in the background; use the Desktop shortcut or `START_APP.bat` to open the page.

## Manual Setup

Open PowerShell in this folder:

```powershell
cd "C:\Users\ANESUISHE CHIPONDA\Documents\mikrotik\mikrotik-hotspot-vouchers-flask"
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## MySQL Setup for VPS

Use MySQL when the app is hosted on a VPS and multiple users/routers will login through the web app.

1. Install MySQL or MariaDB on the VPS.
2. Login to MySQL as root or an admin user.
3. Run:

```sql
SOURCE setup/mysql-setup.sql;
```

Or manually run the SQL inside:

```text
setup/mysql-setup.sql
```

4. Copy:

```text
.env.example
```

to:

```text
.env
```

5. Edit `.env`:

```env
DB_ENGINE=mysql
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_DATABASE=mikrotik_vouchers
MYSQL_USER=voucher_app
MYSQL_PASSWORD=your_mysql_password
KARTE_ADMIN_USERNAME=admin
KARTE_ADMIN_PASSWORD=choose-a-strong-local-admin-password
ENABLE_BACKGROUND_SYNC=1
BACKGROUND_SYNC_SECONDS=300
SECRET_KEY=make-this-a-long-random-secret
```

6. Install requirements and start the app:

```powershell
pip install -r requirements.txt
python app.py
```

The app applies versioned Alembic migrations automatically on first start. Back up an existing database before the first start after an upgrade.

If MySQL is not configured, the app uses local SQLite automatically.

## VPS Hosting

Use the VPS files in:

```text
deploy/ubuntu/
```

Recommended production stack:

- Ubuntu VPS
- MySQL or MariaDB
- Gunicorn using `wsgi:app`
- Nginx reverse proxy
- HTTPS with Certbot or another TLS tool
- WireGuard between the VPS and MikroTik routers

Quick path on the VPS:

```bash
sudo mkdir -p /opt/karte-routeros
sudo rsync -a --delete ./ /opt/karte-routeros/
cd /opt/karte-routeros
sudo bash deploy/ubuntu/install.sh
sudo mysql < setup/mysql-setup.sql
sudo nano .env
sudo systemctl enable --now karte-routeros
sudo systemctl enable --now karte-routeros-sync.timer
sudo systemctl reload nginx
```

Before starting production, set these in `.env`:

```env
APP_ENV=production
DB_ENGINE=mysql
MYSQL_PASSWORD=your_real_mysql_password
SECRET_KEY=a-long-random-secret
KARTE_ADMIN_USERNAME=admin
KARTE_ADMIN_PASSWORD=a-strong-initial-admin-password
TRUST_PROXY=1
SESSION_COOKIE_SECURE=1
ROUTER_ALLOWED_NETWORKS=10.10.10.0/24
ROUTER_ALLOWED_PORTS=8728,8729
ENABLE_BACKGROUND_SYNC=0
```

The app validates production config on startup. If `APP_ENV=production` is set and MySQL, `SECRET_KEY`, or password values are missing/placeholders, Gunicorn exits with a clear error.

See [deploy/ubuntu/README.md](deploy/ubuntu/README.md) for full VPS steps.

## Login Modes

Karte first requires a local Admin or Cashier account. The first administrator is created from `KARTE_ADMIN_USERNAME` and `KARTE_ADMIN_PASSWORD` in production, or through `/account/setup` during local development.

Administrators then use the separate Router Login page with the MikroTik IP/API credentials. Cashiers receive a session for the saved router without seeing router credentials and are limited to packages, vouchers, and sales.

- No account signup is required.
- The router session expires after 30 minutes or when you click **Router Logout**.
- Saved routers are available locally to this app installation.
- For VPS use, connect to routers through WireGuard IP addresses.

## Run

With the virtual environment activated:

```powershell
python app.py
```

Open:

```text
http://localhost:8008
```

You can also double-click:

```text
START_APP.bat
```

If the batch file says the app is not installed yet, double-click `INSTALL.bat` first.

## First Use

1. Open the app.
2. Enter the MikroTik router IP address, API port, username, and password.
3. Click **Connect**.
4. Use **Routers** to add or select saved routers.
5. Use **Save and Test Login** to confirm each router login.
6. Click **Router Settings** if you need to edit the selected router.
7. Click **Find RouterBOARD** to find and save the selected router IP automatically when possible.
8. Enter:
   - Router IP address, for example `192.168.88.1`
   - API port, usually `8728`
   - MikroTik username
   - MikroTik password
9. Click **Save and Test**.
10. Open **Packages** and create counter-staff packages such as `Day-5M`, `Weekly-10M`, or `Monthly-20M`.
11. Open **Bulk Generate** to create voucher batches from those packages.
12. Print the batch or export vouchers from **Vouchers**.
13. Use **Sales** to review recorded voucher sales.

## Voucher Tracking

The database is the source of truth for voucher lifecycle while syncing with the selected MikroTik router:

- **Refresh Status** checks `/ip hotspot user` and `/ip hotspot active`.
- Newly active vouchers are marked **Active** and store first login time, MAC address, IP address, device name, and calculated `expires_at`.
- The first MAC address is bound to the MikroTik hotspot user when RouterOS supports it.
- Expired vouchers are removed from MikroTik and kept locally with status **Expired**.
- Removed vouchers are removed from MikroTik but kept locally with status **Removed**.
- A voucher is not marked expired until RouterOS deletion is confirmed. Failed removals retain their RouterOS ID and are retried.
- Terminal voucher codes that reappear after a router reboot are deleted again.
- Router-only hotspot users are listed under **Unrecognized** for administrator review and are never automatically trusted or deleted.
- Activated voucher codes cannot be renewed back to unused. Create a new voucher instead.
- Local development can run sync in the Flask process. Production uses `karte-routeros-sync.timer` every 60 seconds so Gunicorn workers never duplicate the job.

For VPS cron or a systemd timer, run the sync job explicitly:

```bash
cd /opt/karte-routeros
./venv/bin/flask --app app sync-vouchers
```

Plain-text sync logs are written through the app logger. Set `LOG_LEVEL=INFO` in `.env` for normal operations.

## Packages and Batches

- **Packages** map 1:1 to MikroTik hotspot user profiles.
- Package fields are name, speed limit, validity period, optional data cap, price, and archive status.
- **Bulk Generate** supports up to 2,000 vouchers, configurable code alphabets, and direct batch PDF/CSV exports. Local development pushes immediately; production queues the vouchers for the next serialized sync timer run.
- If a router is rebooted or a user is missing from RouterOS, sync recreates only **Unused** vouchers. Active, expired, and removed codes are never reset to unused.

## Multiple Routers

The app can save multiple MikroTik routers. Use **Routers** to add, edit, delete, or switch routers. Voucher lists, creation, editing, deleting, and printing are filtered to the active router shown at the top of the page.

## MikroTik Setup Script

Open **Setup Script** inside the app to copy a RouterOS script that:

- Supports a VPS-hosted app using WireGuard
- Leaves `ether1` as the internet/WAN port by default
- Adds every other Ethernet port to the hotspot bridge
- Adds wireless/wifi interfaces to the hotspot bridge
- Creates the hotspot bridge, IP address, DHCP pool, DHCP server, hotspot server, NAT rule, and hotspot profile
- Enables the RouterOS API port used by this app
- Creates an API user for the app
- In WireGuard mode, creates a router-side WireGuard tunnel to the VPS and can restrict API access to the VPS WireGuard IP

Change the WAN port on that page before copying the script if your internet cable is not on `ether1`.

For a VPS-hosted app:

1. Set up WireGuard on the VPS first.
2. Copy the VPS WireGuard public key into **Setup Script**.
3. Give every router a unique WireGuard address, for example `10.10.10.2/32`, `10.10.10.3/32`, and so on.
4. Run the generated script on the MikroTik.
5. Add the router public key printed by the script as a peer on the VPS.
6. In this app, add the router using its WireGuard IP without `/32`, for example `10.10.10.2`.

## Pin Like a Windows App

### Option 1: Browser Install App

The app includes `manifest.json`, a service worker, and an app icon. In Microsoft Edge or Google Chrome:

1. Open `http://localhost:8008`.
2. Click the browser menu.
3. Choose **Apps > Install this site as an app** or **Save and share > Install page as app**.
4. Open the installed app.
5. Right-click its taskbar icon and choose **Pin to taskbar**.

### Option 2: Shortcut File

Use this shortcut file:

```text
START_APP.bat
```

The installer creates Desktop and Start Menu shortcuts automatically.

## Notes

- This app stores router settings and vouchers in SQLite by default, or MySQL when `DB_ENGINE=mysql` is set.
- New installs encrypt MikroTik passwords when `cryptography` is installed. Keep the VPS and database private.
- Keep this app on your own trusted Windows computer.
- There is no SMS, WhatsApp, or complicated public payment system.
