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

4. Create the production environment file:

```bash
sudo cp .env.production.example .env
sudo nano .env
sudo chown karte:www-data .env
sudo chmod 640 .env
```

Set:

- `APP_ENV=production`
- `DB_ENGINE=mysql`
- the real MySQL password
- a long random `SECRET_KEY`
- `TRUST_PROXY=1`
- `SESSION_COOKIE_SECURE=1`

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

6. Start the app:

```bash
sudo systemctl enable --now karte-routeros
sudo systemctl reload nginx
```

7. Check health:

```bash
curl http://127.0.0.1:8008/health
curl http://127.0.0.1:8008/healthz
sudo systemctl status karte-routeros
```

## HTTPS

After DNS points to the VPS, use Certbot or your preferred TLS tool:

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

## Router Connections

For routers outside the VPS network, use WireGuard:

1. Create a WireGuard interface on the VPS.
2. Use the in-app **Setup Script** page to generate a MikroTik script.
3. Give each router a unique WireGuard IP.
4. Add each router to the app using its WireGuard IP.

## Logs

```bash
sudo journalctl -u karte-routeros -f
sudo tail -f /var/log/nginx/error.log
```

