# Karte RouterOS Management System - Flask

Simple Flask app for managing MikroTik RouterOS routers, access users, setup scripts, and voucher workflows from a local machine or VPS.

## Folder Structure

```text
mikrotik-hotspot-vouchers-flask/
  app.py
  .env.example
  .env.production.example
  requirements.txt
  requirements-vps.txt
  wsgi.py
  deploy/
    ubuntu/
      README.md
      install.sh
      karte-routeros.service
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
ENABLE_BACKGROUND_SYNC=1
BACKGROUND_SYNC_SECONDS=300
SECRET_KEY=make-this-a-long-random-secret
```

6. Install requirements and start the app:

```powershell
pip install -r requirements.txt
python app.py
```

The app creates the MySQL tables automatically on first start.

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
sudo cp .env.production.example .env
sudo nano .env
sudo systemctl enable --now karte-routeros
sudo systemctl reload nginx
```

Before starting production, set these in `.env`:

```env
APP_ENV=production
DB_ENGINE=mysql
MYSQL_PASSWORD=your_real_mysql_password
SECRET_KEY=a-long-random-secret
TRUST_PROXY=1
SESSION_COOKIE_SECURE=1
```

The app validates production config on startup. If `APP_ENV=production` is set and MySQL, `SECRET_KEY`, or password values are missing/placeholders, Gunicorn exits with a clear error.

See [deploy/ubuntu/README.md](deploy/ubuntu/README.md) for full VPS steps.

## SaaS Mode

The app now has a simple SaaS account layer:

- Users create a Karte account with name, email, and password.
- Each account only sees its own saved routers.
- New accounts start on a 30-day free trial.
- Free-trial accounts can add only 1 router.
- Use **Upgrade** inside the app to increase the router limit manually.
- RouterOS/WinBox-style router login still expires after 30 minutes.
- Routers and vouchers are isolated by the signed-in account.
- The first registered account becomes the owner of any old local routers that existed before the SaaS upgrade.

For a VPS SaaS install:

1. Use MySQL by setting `DB_ENGINE=mysql` in `.env`.
2. Set a strong `SECRET_KEY` in `.env`.
3. Put the app behind HTTPS using Nginx, Caddy, Cloudflare Tunnel, or another reverse proxy.
4. Use WireGuard between the VPS and each MikroTik router.
5. Create one Karte account per customer or operator.
6. Login to the customer account, then connect that customer's router using its WireGuard IP.

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
2. Click **Register** and create a Karte account.
3. Login to the Karte account.
4. Click **Router Login** or **Routers**.
5. Add one or more MikroTik routers.
6. Use **Save and Test Login** to confirm each router login.
7. Select the router you want to work with.
8. Click **Router Settings** if you need to edit the selected router.
9. Click **Find RouterBOARD** to find and save the selected router IP automatically when possible.
10. Enter:
   - Router IP address, for example `192.168.88.1`
   - API port, usually `8728`
   - MikroTik username
   - MikroTik password
11. Click **Save and Test**.
12. Open **Profiles** to create Hotspot user profiles on the selected MikroTik router.
13. Create vouchers using the exact Hotspot profile name that exists on the selected MikroTik router.
14. Choose a voucher time limit from 30 Minutes, 1 Hour, 2 Hours, 1 Day, Weekly, Monthly, or Lifetime.
15. Optional data limits include 500 MB, 1 GB, 2 GB, 5 GB, or Unlimited.

## Voucher Tracking

The voucher dashboard keeps local history while syncing with the selected MikroTik router:

- **Refresh Status** checks `/ip hotspot user` and `/ip hotspot active`.
- Newly active vouchers are marked **Online** or **Activated** and store first login time, MAC address, IP address, and device name when available.
- Expired vouchers are removed from MikroTik and kept locally with status **Expired**.
- Deleted vouchers are removed from MikroTik but kept locally with status **Deleted**.
- The background sync runs automatically every 300 seconds by default. Use `BACKGROUND_SYNC_SECONDS` in `.env` to choose 60 to 300 seconds, or set `ENABLE_BACKGROUND_SYNC=0` to turn it off.

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
- MikroTik passwords are stored in the selected local database. Keep the VPS and database private.
- Keep this app on your own trusted Windows computer.
- There is no online server, payment system, reports, SMS, WhatsApp, or complicated dashboard.
