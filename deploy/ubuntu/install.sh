#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/karte-routeros"
APP_USER="karte"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this script with sudo."
  exit 1
fi

apt update
apt install -y python3 python3-venv python3-pip nginx mysql-server

id "${APP_USER}" >/dev/null 2>&1 || useradd --system --home "${APP_DIR}" --shell /usr/sbin/nologin "${APP_USER}"
mkdir -p "${APP_DIR}"
mkdir -p "${APP_DIR}/storage"

if [[ ! -f "${APP_DIR}/app.py" ]]; then
  echo "Copy the app files to ${APP_DIR} before running the final service steps."
  echo "Example: sudo rsync -a --delete ./ ${APP_DIR}/"
fi

chown -R "${APP_USER}:www-data" "${APP_DIR}"
python3 -m venv "${APP_DIR}/venv"
"${APP_DIR}/venv/bin/pip" install --upgrade pip
"${APP_DIR}/venv/bin/pip" install -r "${APP_DIR}/requirements-vps.txt"

if [[ ! -f "${APP_DIR}/.env" ]]; then
  echo "Missing ${APP_DIR}/.env. Copy your single Karte .env file into place, then run this installer again."
  exit 1
fi
chown "${APP_USER}:www-data" "${APP_DIR}/.env"
chmod 640 "${APP_DIR}/.env"

cp "${APP_DIR}/deploy/ubuntu/karte-routeros.service" /etc/systemd/system/karte-routeros.service
cp "${APP_DIR}/deploy/ubuntu/karte-routeros-sync.service" /etc/systemd/system/karte-routeros-sync.service
cp "${APP_DIR}/deploy/ubuntu/karte-routeros-sync.timer" /etc/systemd/system/karte-routeros-sync.timer
cp "${APP_DIR}/deploy/ubuntu/nginx.conf" /etc/nginx/sites-available/karte-routeros
ln -sf /etc/nginx/sites-available/karte-routeros /etc/nginx/sites-enabled/karte-routeros
rm -f /etc/nginx/sites-enabled/default

systemctl daemon-reload
nginx -t

echo "Next:"
echo "1. Edit ${APP_DIR}/.env"
echo "2. Create the MySQL database/user using setup/mysql-setup.sql or your own secure password"
echo "3. Back up an existing database"
echo "4. Run: sudo -u ${APP_USER} ${APP_DIR}/venv/bin/alembic -c ${APP_DIR}/alembic.ini upgrade head"
echo "5. Run: sudo systemctl enable --now karte-routeros"
echo "6. Run: sudo systemctl enable --now karte-routeros-sync.timer"
echo "7. Run: sudo systemctl reload nginx"
