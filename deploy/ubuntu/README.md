# Ubuntu VPS Deployment

This app is ready to run on a VPS behind Nginx with Gunicorn and MySQL.

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

4. Put the app's single `.env` file at `/opt/karte-routeros/.env`:

```bash
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

7. Start the app:

```bash
sudo systemctl enable --now karte-routeros
sudo systemctl enable --now karte-routeros-sync.timer
sudo systemctl reload nginx
```

8. Check health:

```bash
curl http://127.0.0.1:8008/health
curl http://127.0.0.1:8008/healthz
sudo systemctl status karte-routeros
sudo systemctl status karte-routeros-sync.timer
```

## HTTPS

After DNS points to the VPS, use Certbot or your preferred TLS tool:

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
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
