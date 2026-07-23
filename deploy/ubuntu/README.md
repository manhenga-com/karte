# Ubuntu VPS Deployment

This app is ready to run on a VPS behind Nginx with Gunicorn and MySQL.

> Security note: `.env` is intentionally not tracked. If a real `.env` was ever
> committed or pushed, rotate its MySQL password, Flask secret key, and any
> router or WireGuard credentials before deployment. Removing the file from the
> latest commit does not remove secrets from older Git history.

## Recommended Server

- Ubuntu 22.04 or 24.04
- Python 3.10+
- MySQL or MariaDB
- Nginx
- WireGuard if MikroTik routers connect to the VPS through a private tunnel

## Install

1. Copy this project to the VPS:

```bash
sudo mkdir -p /opt/karte-routeros
sudo rsync -a --delete ./ /opt/karte-routeros/
```

2. Run the helper:

```bash
cd /opt/karte-routeros
sudo bash deploy/ubuntu/install.sh
```

3. Create the MySQL database and user:

```bash
sudo mysql < setup/mysql-setup.sql
```

Change the password in `setup/mysql-setup.sql` first, or create the user manually with a strong password.

4. Create the app's single `.env` file from the safe template:

```bash
sudo cp .env.example .env
sudo nano .env
sudo chown karte:www-data .env
sudo chmod 640 .env
```

Set:

- `APP_ENV=production`
- `DB_ENGINE=mysql`
- the real MySQL password
- a long random `SECRET_KEY`
- `KARTE_ADMIN_USERNAME=admin`
- a strong one-time `KARTE_ADMIN_PASSWORD` for the first local administrator
- `TRUST_PROXY=1`
- `SESSION_COOKIE_SECURE=1`
- `ROUTER_ALLOWED_NETWORKS=10.10.10.0/24` using your real WireGuard subnet
- `ROUTER_ALLOWED_PORTS=8728,8729`
- `ENABLE_BACKGROUND_SYNC=0`
- `KARTE_ADOPTION_SERVER_PUBLIC_KEY` with the VPS WireGuard public key
- `KARTE_ADOPTION_SERVER_ENDPOINT` with the VPS public IP or hostname
- `KARTE_ADOPTION_SERVER_ADDRESS=10.10.10.1/32` using the VPS tunnel IP
- `KARTE_ADOPTION_ROUTER_ADDRESS=10.10.10.2/32` as the next router tunnel IP
- `KARTE_ADOPTION_SERVER_PORT=51820`

Generate a secret with:

```bash
python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
```

5. Edit Nginx server name:

```bash
sudo nano /etc/nginx/sites-available/karte-routeros
```

Replace `example.com` with your domain.

6. Back up an existing database, then review/apply the migration:

```bash
sudo -u karte /opt/karte-routeros/venv/bin/alembic -c /opt/karte-routeros/alembic.ini upgrade head
```

7. Run the production preflight:

```bash
sudo -u karte /opt/karte-routeros/venv/bin/flask --app app deployment-check
```

Do not start the service until this reports `Deployment check passed`.

8. Enable HTTPS before starting the app:

```bash
sudo certbot --nginx --redirect -d your-domain.com
```

9. Start the app:

```bash
sudo systemctl enable --now karte-routeros
sudo systemctl enable --now karte-routeros-sync.timer
sudo systemctl reload nginx
```

10. Check health:

```bash
curl http://127.0.0.1:8008/health
curl http://127.0.0.1:8008/healthz
sudo systemctl status karte-routeros
sudo systemctl status karte-routeros-sync.timer
```

## HTTPS

After DNS points to the VPS, use Certbot or your preferred TLS tool. The install helper already installs Certbot:

```bash
sudo certbot --nginx --redirect -d your-domain.com
```

Do not expose port `8008` publicly. Only Nginx should reach Gunicorn, and router API targets must stay inside the private networks listed in `ROUTER_ALLOWED_NETWORKS`.

## Router Connections

For routers outside the VPS network, use WireGuard:

1. Create a WireGuard interface on the VPS.
2. Use the in-app **Setup Script** page to generate a MikroTik script.
3. Give each router a unique WireGuard IP.
4. Add each router to the app using its WireGuard IP.

## Logs

```bash
sudo journalctl -u karte-routeros -f
sudo journalctl -u karte-routeros-sync.service -f
sudo tail -f /var/log/nginx/error.log
```
