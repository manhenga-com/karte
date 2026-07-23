from __future__ import annotations

import base64
import csv
import hashlib
import io
import logging
import os
import ipaddress
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from contextlib import closing, contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps
from pathlib import Path

import click
from flask import Flask, Response, flash, g, has_request_context, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

try:
    import routeros_api
except ImportError:  # The app shows a friendly setup error when router actions are used.
    routeros_api = None

try:
    import pymysql
except ImportError:  # MySQL is optional unless DB_ENGINE=mysql is selected.
    pymysql = None

try:
    from sqlalchemy import create_engine
    from sqlalchemy.engine import URL
except ImportError:  # SQLAlchemy is required when MySQL is selected.
    create_engine = None
    URL = None

try:
    from cryptography.fernet import Fernet
except ImportError:
    Fernet = None


BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR / "storage"
DATABASE = STORAGE_DIR / "database.sqlite"
SECRET_KEY_PATH = STORAGE_DIR / "secret_key.txt"
ROUTER_SESSION_SECONDS = 30 * 60
APP_SESSION_SECONDS = 8 * 60 * 60
SYNC_THREAD_STARTED = False
MYSQL_ENGINE = None
LOGGER = logging.getLogger("karte")
LOCAL_SYNC_LOCK = threading.Lock()


def create_app() -> Flask:
    app = Flask(__name__)
    STORAGE_DIR.mkdir(exist_ok=True)
    load_env_file()
    configure_logging()
    validate_startup_config()
    app.config["SECRET_KEY"] = load_secret_key()
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=ROUTER_SESSION_SECONDS)
    app.config["SESSION_REFRESH_EACH_REQUEST"] = False
    configure_http_settings(app)
    init_db()
    purge_expired_router_sessions()
    ensure_bootstrap_admin()
    start_background_sync(app)

    public_endpoints = {
        "account_setup",
        "app_login",
        "health",
        "healthz",
        "legacy_login_redirect",
        "manifest",
        "router_setup_script",
        "service_worker",
        "static",
    }
    public_paths = {
        "/adopt-router",
        "/router-setup-script",
    }

    @app.before_request
    def protect_post_requests():
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            expected = session.get("csrf_token", "")
            supplied = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
            if not expected or not supplied or not secrets.compare_digest(str(expected), str(supplied)):
                return "Invalid or missing CSRF token.", 400

    @app.before_request
    def require_app_and_router_login():
        request_path = request.path.rstrip("/") or "/"
        if request.endpoint in public_endpoints or request_path in public_paths or request.endpoint is None:
            return None

        if not app_user_session_active():
            clear_app_session()
            return redirect(url_for("app_login", next=request.full_path if request.query_string else request.path))

        if request.endpoint in {"app_logout", "login", "user_management", "create_user", "edit_user"}:
            return None

        if router_session_active():
            return None

        had_login = bool(session.get("router_session_token"))
        clear_router_session()
        if had_login:
            flash("Router login expired after 30 minutes. Please login again.", "warning")
        user = current_user()
        if user and row_value(user, "role") == "cashier":
            router = first_router()
            if router:
                start_router_session(int(router["id"]), router)
                return None
            flash("No router is configured. Ask an administrator to add one.", "warning")
            clear_app_session()
            return redirect(url_for("app_login"))
        return redirect(url_for("login", next=request.full_path if request.query_string else request.path))

    @app.after_request
    def prevent_dynamic_page_cache(response):
        if request.endpoint not in {"static", "manifest", "service_worker"}:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; "
            "object-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; connect-src 'self'"
        )
        return response

    @app.teardown_request
    def close_router_clients(_error=None):
        for client in getattr(g, "router_clients", []):
            client.close()

    @app.context_processor
    def inject_active_router():
        return {
            "active_router": get_active_router() if router_session_active() else None,
            "current_user": current_user(),
            "session_minutes_left": session_minutes_left(),
            "csrf_token": get_csrf_token(),
        }

    @app.template_filter("time_remaining")
    def time_remaining_filter(voucher):
        return voucher_time_remaining(voucher)

    @app.template_filter("data_remaining")
    def data_remaining_filter(voucher):
        return voucher_data_remaining(voucher)

    @app.template_filter("data_size")
    def data_size_filter(value):
        return format_bytes(parse_int(value))

    @app.template_filter("money")
    def money_filter(value):
        return format_money(value)

    @app.route("/")
    def home():
        if not router_session_active():
            return redirect(url_for("login"))
        return render_template("home.html", summary=dashboard_summary())

    @app.route("/health")
    def health():
        return "ok mysql-alembic-v1 voucher-lifecycle-v2 local-rbac-v1 router-ip-session-v1 wireguard-v1\n", 200, {"Content-Type": "text/plain; charset=utf-8"}

    @app.route("/healthz")
    def healthz():
        with closing(get_db()) as db:
            db.execute("SELECT 1").fetchone()
        return "ok\n", 200, {"Content-Type": "text/plain; charset=utf-8"}

    @app.route("/account/login", methods=["GET", "POST"])
    def app_login():
        if app_user_session_active():
            return redirect(safe_next_url(request.values.get("next")) or url_for("home"))

        next_url = request.values.get("next", "")
        if request.method == "POST":
            if login_rate_limited("account"):
                flash("Too many failed login attempts. Wait a few minutes and try again.", "danger")
                return render_template(
                    "account_login.html",
                    username=request.form.get("username", "").strip(),
                    next_url=next_url,
                    setup_available=user_count() == 0,
                ), 429

            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = get_user_by_username(username)
            if not user or not bool(int(row_value(user, "active", "0"))) or not check_password_hash(row_value(user, "password_hash"), password):
                record_login_attempt("account", False)
                flash("Incorrect username or password.", "danger")
                return render_template(
                    "account_login.html",
                    username=username,
                    next_url=next_url,
                    setup_available=user_count() == 0,
                ), 401

            clear_login_attempts("account")
            start_app_session(user)
            update_user_last_login(int(user["id"]))
            destination = safe_next_url(next_url)
            if row_value(user, "role") == "cashier":
                router = first_router()
                if router:
                    start_router_session(int(router["id"]), router)
                destination = destination or url_for("vouchers")
            else:
                destination = destination or url_for("login")
            return redirect(destination)

        return render_template(
            "account_login.html",
            username="",
            next_url=next_url,
            setup_available=user_count() == 0,
        )

    @app.route("/account/setup", methods=["GET", "POST"])
    def account_setup():
        if user_count() > 0:
            return redirect(url_for("app_login"))

        if request.method == "POST":
            data = user_from_form(force_role="admin")
            error = validate_user(data, require_password=True)
            if error:
                flash(error, "danger")
                return render_template("account_setup.html", user=data)
            user_id = insert_user(data)
            user = get_user(user_id)
            start_app_session(user)
            flash("Administrator account created. Add the first router to continue.", "success")
            return redirect(url_for("login"))

        return render_template("account_setup.html", user={"username": "admin", "role": "admin", "active": "1"})

    @app.post("/account/logout")
    def app_logout():
        clear_router_session()
        clear_app_session()
        flash("Signed out of Karte.", "success")
        return redirect(url_for("app_login"))

    @app.route("/account/login-v2")
    def legacy_login_redirect():
        return redirect(url_for("app_login"))

    @app.route("/account/users")
    @admin_required
    def user_management():
        return render_template("users.html", users=list_users())

    @app.route("/account/users/create", methods=["GET", "POST"])
    @admin_required
    def create_user():
        user = user_from_form() if request.method == "POST" else {
            "username": "",
            "password": "",
            "role": "cashier",
            "active": "1",
        }
        if request.method == "POST":
            error = validate_user(user, require_password=True)
            if error:
                flash(error, "danger")
            else:
                user_id = insert_user(user)
                audit_log(current_user_id(), None, "user", user_id, "create", f"Created {user['role']} {user['username']}")
                flash("User account created.", "success")
                return redirect(url_for("user_management"))
        return render_template("user_form.html", user=user, mode="create")

    @app.route("/account/users/<int:user_id>/edit", methods=["GET", "POST"])
    @admin_required
    def edit_user(user_id: int):
        existing = get_user(user_id)
        if not existing:
            flash("User account not found.", "warning")
            return redirect(url_for("user_management"))

        user = user_from_form(existing) if request.method == "POST" else {
            "username": row_value(existing, "username"),
            "password": "",
            "role": row_value(existing, "role"),
            "active": row_value(existing, "active", "1"),
        }
        if request.method == "POST":
            error = validate_user(user, require_password=False, existing_user_id=user_id)
            removing_admin = (
                row_value(existing, "role") == "admin"
                and bool(int(row_value(existing, "active", "0")))
                and (user["role"] != "admin" or user["active"] != "1")
            )
            if removing_admin and active_admin_count() <= 1:
                error = "Keep at least one active administrator."
            if error:
                flash(error, "danger")
            else:
                update_user(user_id, user)
                audit_log(current_user_id(), None, "user", user_id, "update", f"Updated user {user['username']}")
                flash("User account updated.", "success")
                return redirect(url_for("user_management"))
        return render_template("user_form.html", user=user, mode="edit")

    @app.route("/login", methods=["GET", "POST"])
    @admin_required
    def login():
        selected_router_id = parse_positive_int(request.values.get("router_id"), 0)
        router = login_defaults(selected_router_id)
        next_url = request.values.get("next", "")

        if request.method == "POST":
            if router_login_rate_limited():
                flash("Too many failed login attempts. Wait a few minutes and try again.", "danger")
                return render_template("login.html", router=router, next_url=next_url), 429

            data = router_from_form(router)
            error = validate_router(data)
            if error:
                record_router_login_attempt(False)
                flash(error, "danger")
                return render_template("login.html", router=data, next_url=next_url)

            try:
                RouterClient(data).test_connection()
            except Exception as exc:
                record_router_login_attempt(False)
                flash(f"Router login failed: {exc}", "danger")
                return render_template("login.html", router=data, next_url=next_url)

            try:
                router_id = save_login_router(data)
            except ValueError as exc:
                record_router_login_attempt(False)
                flash(str(exc), "warning")
                return render_template("login.html", router=data, next_url=next_url)
            try:
                test_and_reconcile_router(get_router(router_id), data)
            except Exception as exc:
                LOGGER.warning("login reconciliation failed router=%s error=%s", router_id, exc)
                flash(f"Router login worked, but reconciliation could not finish: {exc}", "warning")
            clear_router_login_attempts()
            start_router_session(router_id, data)
            flash("Router login successful. Session will expire in 30 minutes.", "success")
            return redirect(safe_next_url(next_url) or url_for("home"))

        return render_template("login.html", router=router, next_url=next_url)

    @app.post("/logout")
    def logout():
        clear_router_session()
        flash("Logged out from the router session.", "success")
        return redirect(url_for("login"))

    @app.route("/settings", methods=["GET", "POST"])
    @admin_required
    def settings():
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))

        if request.method == "POST":
            action = request.form.get("action")
            data = router_from_form(router)

            if action == "discover":
                port = int(data["api_port"]) if data["api_port"].isdigit() else 8728
                result = discover_routerboard(port)
                if result:
                    data["router_ip"] = result["ip"]
                    api_note = "API port is open" if result["api_open"] else "API port did not respond yet"
                    flash(
                        f"Found RouterBOARD IP {result['ip']} using {result['source']}. {api_note}.",
                        "success" if result["api_open"] else "warning",
                    )
                else:
                    flash("Could not find a RouterBOARD automatically. Enter the router IP address manually.", "warning")
                return render_template("settings.html", settings=data)

            error = validate_router(data)
            if error:
                flash(error, "danger")
                return render_template("settings.html", settings=data)

            update_router(router["id"], data)
            start_router_session(router["id"], data)

            if request.form.get("action") == "test":
                try:
                    test_and_reconcile_router(get_router(int(router["id"])), data)
                except Exception as exc:
                    flash(f"Settings saved, but connection failed: {exc}", "danger")
                    return redirect(url_for("settings"))

                flash("Settings saved. Router connection works.", "success")
            else:
                flash("Router settings saved.", "success")

            return redirect(url_for("settings"))

        return render_template("settings.html", settings=router_to_safe_form_data(router))

    @app.route("/settings/discover")
    @admin_required
    def discover_settings():
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))

        settings_data = router_to_form_data(router)
        settings_data.update(active_router_settings(router))
        port = int(settings_data["api_port"]) if settings_data["api_port"].isdigit() else 8728
        result = discover_routerboard(port)

        if result:
            settings_data["router_ip"] = result["ip"]
            update_router(router["id"], settings_data)
            start_router_session(router["id"], settings_data)
            api_note = "API port is open" if result["api_open"] else "API port did not respond yet"
            flash(
                f"Found RouterBOARD IP {result['ip']} using {result['source']}. {api_note}.",
                "success" if result["api_open"] else "warning",
            )
        else:
            flash("Could not find a RouterBOARD automatically. Enter the router IP address manually.", "warning")

        return redirect(url_for("settings"))

    @app.route("/routers")
    @admin_required
    def routers():
        router = require_active_router()
        return render_template("routers.html", routers=[router] if router else [])

    @app.route("/routers/add", methods=["GET", "POST"])
    @admin_required
    def routers_add():
        router = {
            "name": "",
            "router_ip": "",
            "api_port": "8728",
            "router_username": "",
            "router_password": "",
        }

        if request.method == "POST":
            data = router_from_form(router)
            error = validate_router(data)
            if error:
                flash(error, "danger")
                return render_template("router_form.html", router=data, mode="add")

            try:
                RouterClient(data).test_connection()
            except Exception as exc:
                flash(f"Router login failed: {exc}", "danger")
                return render_template("router_form.html", router=data, mode="add")

            try:
                router_id = insert_router(data)
            except ValueError as exc:
                flash(str(exc), "warning")
                return redirect(url_for("routers"))
            try:
                test_and_reconcile_router(get_router(router_id), data)
            except Exception as exc:
                LOGGER.warning("router add reconciliation failed router=%s error=%s", router_id, exc)
                flash(f"Router saved, but reconciliation could not finish: {exc}", "warning")
            start_router_session(router_id, data)
            flash("Router saved and selected.", "success")
            return redirect(url_for("vouchers"))

        return render_template("router_form.html", router=router, mode="add")

    @app.route("/routers/<int:router_id>/edit", methods=["GET", "POST"])
    @admin_required
    def routers_edit(router_id: int):
        router = get_authorized_router(router_id)
        if not router:
            flash("Router not found.", "warning")
            return redirect(url_for("routers"))

        if request.method == "POST":
            data = router_from_form(router)
            error = validate_router(data)
            if error:
                flash(error, "danger")
                data["id"] = router_id
                return render_template("router_form.html", router=data, mode="edit")

            update_router(router_id, data)
            try:
                test_and_reconcile_router(get_router(router_id), data)
            except Exception as exc:
                flash(f"Router saved, but connection or reconciliation failed: {exc}", "danger")
                data["id"] = router_id
                return render_template("router_form.html", router=data, mode="edit")
            start_router_session(router_id, data)
            flash("Router saved and selected.", "success")
            return redirect(url_for("routers"))

        form_router = router_to_safe_form_data(router)
        form_router["id"] = router_id
        return render_template("router_form.html", router=form_router, mode="edit")

    @app.post("/routers/<int:router_id>/use")
    @admin_required
    def routers_use(router_id: int):
        router = get_authorized_router(router_id)
        if not router:
            flash("Router not found.", "warning")
            return redirect(url_for("routers"))

        flash(f"Login to {router['name']} to switch routers.", "info")
        return redirect(url_for("login", router_id=router_id, next=url_for("routers")))

    @app.post("/routers/<int:router_id>/delete")
    @admin_required
    def routers_delete(router_id: int):
        router = get_authorized_router(router_id)
        if not router:
            flash("Router not found.", "warning")
            return redirect(url_for("routers"))

        try:
            delete_router(router_id)
        except ValueError as exc:
            flash(str(exc), "warning")
            return redirect(url_for("routers"))
        if session.get("router_id") == router_id:
            clear_router_session()
        flash(f"Deleted router {router['name']}.", "success")
        return redirect(url_for("routers"))

    @app.route("/router-setup-script", methods=["GET", "POST"])
    @app.route("/adopt-router", methods=["GET", "POST"])
    def router_setup_script():
        # This page is intentionally public. Never prefill it from saved router
        # records because those credentials belong behind the authenticated UI.
        options = router_setup_options_from_request({})
        script = build_router_setup_script(options)
        return render_template("router_setup_script.html", options=options, script=script)

    @app.route("/wireguard", methods=["GET", "POST"])
    @admin_required
    def wireguard_interfaces():
        active_router = require_active_router()
        if not active_router:
            return redirect(url_for("login"))
        form = wireguard_interface_from_form() if request.method == "POST" else default_wireguard_interface()
        form["router_id"] = str(active_router["id"])
        routers_for_form = [active_router]

        if request.method == "POST":
            error = validate_wireguard_interface(form)
            if error:
                flash(error, "danger")
            else:
                interface_id = insert_wireguard_interface(form)
                flash("WireGuard interface saved. Copy the Ubuntu setup script when you are ready.", "success")
                return redirect(url_for("wireguard_interface_script", interface_id=interface_id))

        return render_template(
            "wireguard.html",
            form=form,
            interfaces=list_wireguard_interfaces(int(active_router["id"])),
            routers=routers_for_form,
        )

    @app.route("/wireguard/<int:interface_id>/script")
    @admin_required
    def wireguard_interface_script(interface_id: int):
        active_router = require_active_router()
        if not active_router:
            return redirect(url_for("login"))
        interface = get_wireguard_interface(interface_id, int(active_router["id"]))
        if not interface:
            flash("WireGuard interface not found.", "warning")
            return redirect(url_for("wireguard_interfaces"))

        return render_template(
            "wireguard_script.html",
            interface=interface,
            script=build_wireguard_interface_script(interface),
        )

    @app.route("/profiles", methods=["GET", "POST"])
    @admin_required
    def hotspot_profiles():
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))

        profile = hotspot_profile_from_form() if request.method == "POST" else default_hotspot_profile()
        client = RouterClient(active_router_settings(router))

        if request.method == "POST":
            error = validate_hotspot_profile(profile)
            if error:
                flash(error, "danger")
            else:
                try:
                    if client.find_hotspot_profile(profile["name"]):
                        flash("A hotspot profile with this name already exists on the MikroTik router.", "danger")
                    else:
                        client.create_hotspot_profile(profile)
                        flash("Hotspot profile created on the MikroTik router.", "success")
                        return redirect(url_for("hotspot_profiles"))
                except Exception as exc:
                    flash(f"Could not create hotspot profile: {exc}", "danger")

        profiles = []
        try:
            profiles = client.list_hotspot_profiles()
        except Exception as exc:
            flash(f"Could not load hotspot profiles from MikroTik router: {exc}", "danger")

        return render_template("profiles.html", profiles=profiles, profile=profile)

    @app.route("/packages", methods=["GET", "POST"])
    def packages():
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))

        package = package_from_form() if request.method == "POST" else default_package()

        if request.method == "POST":
            user = current_user()
            if not user or row_value(user, "role") != "admin":
                flash("Administrator access is required.", "danger")
                return redirect(url_for("packages"))
            error = validate_package(package)
            if error:
                flash(error, "danger")
            else:
                package_id = insert_package(package, int(router["id"]))
                audit_log(current_user_id(), int(router["id"]), "package", package_id, "create", f"Package {package['name']} created")
                try:
                    RouterClient(active_router_settings(router)).ensure_hotspot_profile(package_to_hotspot_profile(package))
                    flash("Package saved and MikroTik hotspot profile updated.", "success")
                except Exception as exc:
                    flash(f"Package saved locally, but MikroTik profile update failed: {exc}", "warning")
                return redirect(url_for("packages"))

        return render_template("packages.html", packages=list_packages(int(router["id"]), include_archived=True), package=package)

    @app.route("/packages/<int:package_id>/edit", methods=["GET", "POST"])
    @admin_required
    def edit_package(package_id: int):
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))

        existing = get_package(package_id, int(router["id"]))
        if not existing:
            flash("Package not found.", "warning")
            return redirect(url_for("packages"))

        package = package_from_form(existing) if request.method == "POST" else package_to_form(existing)
        if request.method == "POST":
            error = validate_package(package)
            if error:
                flash(error, "danger")
                return render_template("package_form.html", package=package)

            update_package(package_id, package, int(router["id"]))
            audit_log(current_user_id(), int(router["id"]), "package", package_id, "update", f"Package {package['name']} updated")
            try:
                RouterClient(active_router_settings(router)).ensure_hotspot_profile(package_to_hotspot_profile(package))
                flash("Package updated and MikroTik hotspot profile updated.", "success")
            except Exception as exc:
                flash(f"Package updated locally, but MikroTik profile update failed: {exc}", "warning")
            return redirect(url_for("packages"))

        return render_template("package_form.html", package=package)

    @app.post("/packages/<int:package_id>/archive")
    @admin_required
    def archive_package(package_id: int):
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))
        package = get_package(package_id, int(router["id"]))
        if not package:
            flash("Package not found.", "warning")
            return redirect(url_for("packages"))
        set_package_archived(package_id, int(router["id"]), not bool(int(row_value(package, "archived", "0"))))
        audit_log(current_user_id(), int(router["id"]), "package", package_id, "archive", f"Package {row_value(package, 'name')} archive toggled")
        flash("Package status updated.", "success")
        return redirect(url_for("packages"))

    @app.route("/hotspot/active")
    @admin_required
    def active_hotspot_users():
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))

        client = RouterClient(active_router_settings(router))
        active_users = []
        summary = {
            "connected": 0,
            "total_data": 0,
            "total_data_label": "0 B",
            "router_name": row_value(router, "name", "Router"),
            "refreshed_at": timestamp(),
        }

        try:
            active_users = client.connected_hotspot_users()
        except Exception as exc:
            flash(f"Could not load connected hotspot users from MikroTik: {exc}", "danger")

        summary["connected"] = len(active_users)
        summary["total_data"] = sum(user["data_total"] for user in active_users if user["data_total"] is not None)
        summary["total_data_label"] = format_bytes(summary["total_data"])

        return render_template("active_users.html", active_users=active_users, summary=summary)

    @app.post("/hotspot/active/disconnect")
    @admin_required
    def disconnect_active_hotspot_user():
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))
        username = request.form.get("username", "").strip()
        if not username:
            flash("Choose a connected user to disconnect.", "warning")
            return redirect(url_for("active_hotspot_users"))
        try:
            RouterClient(active_router_settings(router)).remove_active_hotspot_sessions(username)
            audit_log(current_user_id(), int(router["id"]), "active_user", None, "disconnect", f"Disconnected {username}")
            flash(f"Disconnected {username}.", "success")
        except Exception as exc:
            flash(f"Could not disconnect user: {exc}", "danger")
        return redirect(url_for("active_hotspot_users"))

    @app.route("/reconciliation/issues")
    @admin_required
    def reconciliation_issues():
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))
        return render_template(
            "reconciliation_issues.html",
            issues=list_reconciliation_issues(int(router["id"])),
        )

    @app.post("/reconciliation/issues/<int:issue_id>/status")
    @admin_required
    def update_reconciliation_issue_status(issue_id: int):
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))

        status = request.form.get("status", "").strip().lower()
        if status not in {"open", "acknowledged", "resolved"}:
            flash("Choose a valid review status.", "warning")
            return redirect(url_for("reconciliation_issues"))

        issue = get_reconciliation_issue(issue_id, int(router["id"]))
        if not issue:
            flash("Reconciliation issue not found.", "warning")
            return redirect(url_for("reconciliation_issues"))

        set_reconciliation_issue_status(issue_id, int(router["id"]), status)
        audit_log(
            current_user_id(),
            int(router["id"]),
            "reconciliation_issue",
            issue_id,
            "review",
            f"Marked unrecognized router user {row_value(issue, 'remote_name')} as {status}",
        )
        flash("Review status updated. No RouterOS user was changed.", "success")
        return redirect(url_for("reconciliation_issues"))

    @app.route("/vouchers/bulk", methods=["GET", "POST"])
    def bulk_vouchers():
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))

        packages_for_form = list_packages(int(router["id"]))
        form = voucher_batch_from_form() if request.method == "POST" else default_voucher_batch()

        if request.method == "POST":
            error = validate_voucher_batch(form, packages_for_form)
            if error:
                flash(error, "danger")
            else:
                package = get_package(parse_positive_int(form["package_id"], 0), int(router["id"]))
                if not package:
                    flash("Choose a valid package.", "danger")
                else:
                    voucher_ids, batch_id = create_voucher_batch(router, package, form)
                    push_vouchers_to_router_async(app, router, active_router_settings(router), voucher_ids, batch_id)
                    audit_log(current_user_id(), int(router["id"]), "voucher_batch", batch_id, "create", f"Generated {len(voucher_ids)} vouchers")
                    push_message = "queued for the scheduled router sync" if is_production() else "being pushed to the router"
                    flash(f"Batch #{batch_id} created with {len(voucher_ids)} vouchers and is {push_message}.", "success")
                    return redirect(url_for("voucher_batches"))

        return render_template("voucher_bulk.html", form=form, packages=packages_for_form, router=router)

    @app.route("/vouchers/batches")
    def voucher_batches():
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))
        return render_template("voucher_batches.html", batches=list_voucher_batches(int(router["id"])))

    @app.route("/vouchers/batches/<int:batch_id>/print")
    def print_voucher_batch(batch_id: int):
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))
        batch = get_voucher_batch(batch_id, int(router["id"]))
        if not batch:
            flash("Voucher batch not found.", "warning")
            return redirect(url_for("voucher_batches"))
        return render_template("print.html", vouchers=list_vouchers_by_batch(int(router["id"]), batch_id))

    @app.route("/vouchers/batches/<int:batch_id>/csv")
    def export_voucher_batch_csv(batch_id: int):
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))
        batch = get_voucher_batch(batch_id, int(router["id"]))
        if not batch:
            flash("Voucher batch not found.", "warning")
            return redirect(url_for("voucher_batches"))

        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(VOUCHER_EXPORT_COLUMNS)
        for voucher in list_vouchers_by_batch(int(router["id"]), batch_id):
            writer.writerow(voucher_export_row(voucher))
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=karte-batch-{batch_id}.csv"},
        )

    @app.route("/vouchers/batches/<int:batch_id>/pdf")
    def export_voucher_batch_pdf(batch_id: int):
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))
        batch = get_voucher_batch(batch_id, int(router["id"]))
        if not batch:
            flash("Voucher batch not found.", "warning")
            return redirect(url_for("voucher_batches"))
        try:
            pdf_data = build_vouchers_pdf(
                list_vouchers_by_batch(int(router["id"]), batch_id),
                router,
            )
        except RuntimeError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("voucher_batches"))
        return Response(
            pdf_data,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=karte-batch-{batch_id}.pdf"},
        )

    @app.route("/sales")
    def sales():
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))
        return render_template(
            "sales.html",
            summary=sales_summary(int(router["id"])),
            sales=list_sales(int(router["id"])),
        )

    @app.route("/vouchers")
    def vouchers():
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))

        state = voucher_query_state()
        page = parse_positive_int(request.args.get("page"), 1)
        per_page = int(state["per_page"])
        counts = voucher_status_counts(router["id"])
        total = count_filtered_vouchers(int(router["id"]), state)
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, total_pages)
        offset = (page - 1) * per_page
        rows = list_filtered_vouchers(int(router["id"]), state, limit=per_page, offset=offset)
        sort_urls = {
            key: voucher_page_url(
                state,
                page=1,
                sort=key,
                direction=("desc" if state["sort"] == key and state["direction"] == "asc" else "asc"),
            )
            for key in VOUCHER_SORT_COLUMNS
        }
        status_urls = {
            status: voucher_page_url(state, status=status, page=1)
            for status in ["all", *DISPLAY_VOUCHER_STATUSES]
        }
        active_filters = voucher_active_filters(state)
        page_start = max(1, page - 2)
        page_end = min(total_pages, page + 2)

        return render_template(
            "vouchers.html",
            vouchers=rows,
            counts=counts,
            statuses=DISPLAY_VOUCHER_STATUSES,
            selected_status=state["status"],
            state=state,
            profiles=list_voucher_profiles(int(router["id"])),
            sort_urls=sort_urls,
            status_urls=status_urls,
            active_filters=active_filters,
            clear_filters_url=voucher_page_url(
                state,
                q="",
                status="all",
                profile="",
                date_from="",
                date_to="",
                page=1,
            ),
            export_query=voucher_query_params(state, page=None),
            pagination={
                "page": page,
                "per_page": per_page,
                "total": total,
                "total_pages": total_pages,
                "has_prev": page > 1,
                "has_next": page < total_pages,
                "first_item": offset + 1 if total else 0,
                "last_item": min(offset + len(rows), total),
                "previous_url": voucher_page_url(state, page=page - 1) if page > 1 else "",
                "next_url": voucher_page_url(state, page=page + 1) if page < total_pages else "",
                "pages": [
                    {"number": number, "url": voucher_page_url(state, page=number)}
                    for number in range(page_start, page_end + 1)
                ],
            },
        )

    @app.route("/vouchers/export/csv")
    def export_vouchers_csv():
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))

        state = voucher_query_state()
        voucher_ids = selected_voucher_ids()
        rows = list_vouchers_for_export(router["id"], state, voucher_ids)
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(VOUCHER_EXPORT_COLUMNS)
        for row in rows:
            writer.writerow(voucher_export_row(row))

        filename = f"karte-vouchers-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    @app.route("/vouchers/export/pdf")
    def export_vouchers_pdf():
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))

        state = voucher_query_state()
        voucher_ids = selected_voucher_ids()
        rows = list_vouchers_for_export(router["id"], state, voucher_ids)
        try:
            pdf_data = build_vouchers_pdf(rows, router)
        except RuntimeError as exc:
            flash(str(exc), "danger")
            return redirect(voucher_page_url(state))

        filename = f"karte-vouchers-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"
        return Response(
            pdf_data,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    @app.post("/vouchers/sync")
    def sync_vouchers():
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))

        try:
            summary = sync_router_vouchers(router, active_router_settings(router))
        except Exception as exc:
            flash(f"Could not refresh voucher status from MikroTik: {exc}", "danger")
            return redirect(url_for("vouchers"))

        flash(
            f"Status refreshed: {summary['checked']} checked, {summary['online']} online, {summary['expired']} expired.",
            "success",
        )
        return redirect(url_for("vouchers"))

    @app.route("/vouchers/create", methods=["GET", "POST"])
    def create_voucher():
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))

        profile_names = hotspot_profile_names(router)
        packages_for_form = list_packages(int(router["id"]))

        if request.method == "POST":
            data = voucher_from_form()
            data["status"] = "unused"
            if data.get("package_id"):
                package = get_package(parse_positive_int(data["package_id"], 0), int(router["id"]))
                if package:
                    data = apply_package_to_voucher(data, package)
            error = validate_voucher(data)
            if error:
                flash(error, "danger")
                return render_template("voucher_form.html", voucher=data, mode="create", profile_names=profile_names, packages=packages_for_form)

            if get_voucher_by_username(data["username"], router["id"]):
                flash("This router already has a local voucher with this username.", "danger")
                return render_template("voucher_form.html", voucher=data, mode="create", profile_names=profile_names, packages=packages_for_form)

            data["routeros_id"] = ""
            try:
                voucher_id = insert_voucher(data, router["id"])
            except Exception as exc:
                LOGGER.warning("voucher database create failed router=%s voucher=%s error=%s", router["id"], data["username"], exc)
                flash(f"Could not save the voucher: {exc}", "danger")
                return render_template("voucher_form.html", voucher=data, mode="create", profile_names=profile_names, packages=packages_for_form)

            audit_log(current_user_id(), int(router["id"]), "voucher", voucher_id, "create", f"Voucher {data['username']} created")
            try:
                routeros_id = RouterClient(active_router_settings(router)).create_voucher(data)
                update_voucher_sync_fields(
                    voucher_id,
                    int(router["id"]),
                    {"routeros_id": routeros_id or "", "last_error": "", "retry_count": 0},
                )
                flash("Voucher created on the MikroTik router.", "success")
            except Exception as exc:
                record_voucher_sync_failure(voucher_id, int(router["id"]), exc, "")
                LOGGER.warning("voucher queued for router sync router=%s voucher=%s error=%s", router["id"], data["username"], exc)
                flash("Voucher saved. The router is unavailable, so Karte queued it for the next sync.", "warning")
            return redirect(url_for("print_vouchers", voucher_id=voucher_id))

        voucher = {
            "username": f"user{secrets.randbelow(9000) + 1000}",
            "password": random_code(8),
            "profile": "default",
            "time_limit": "1h",
            "data_limit": "",
            "shared_users": "1",
            "price": "0.00",
            "expiry_date": "",
            "status": "unused",
            "comment": "",
        }
        if packages_for_form:
            voucher["package_id"] = str(packages_for_form[0]["id"])
            voucher = apply_package_to_voucher(voucher, packages_for_form[0])
        if profile_names and not voucher.get("package_id") and voucher["profile"] not in profile_names:
            voucher["profile"] = profile_names[0]
        return render_template("voucher_form.html", voucher=voucher, mode="create", profile_names=profile_names, packages=packages_for_form)

    @app.route("/vouchers/<int:voucher_id>")
    def voucher_details(voucher_id: int):
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))

        voucher = get_voucher(voucher_id, router["id"])
        if not voucher:
            flash("Voucher not found.", "warning")
            return redirect(url_for("vouchers"))

        return render_template("voucher_details.html", voucher=voucher)

    @app.route("/vouchers/<int:voucher_id>/edit", methods=["GET", "POST"])
    def edit_voucher(voucher_id: int):
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))

        voucher = get_voucher(voucher_id, router["id"])
        if not voucher:
            flash("Voucher not found.", "warning")
            return redirect(url_for("vouchers"))

        profile_names = hotspot_profile_names(router)
        packages_for_form = list_packages(int(router["id"]), include_archived=True)

        if request.method == "POST":
            if (
                voucher_has_usage_evidence(voucher)
                or voucher_should_expire(
                    voucher,
                    row_value(voucher, "uptime_used"),
                    parse_int(row_value(voucher, "data_used")),
                )
                or row_value(voucher, "status") in ["active", "used", "expired", "removed", "deleted"]
            ):
                flash("This voucher has already entered its lifecycle and cannot be reused or reset. Create a new voucher instead.", "warning")
                return redirect(url_for("voucher_details", voucher_id=voucher_id))
            data = voucher_from_form()
            if data.get("package_id"):
                package = get_package(parse_positive_int(data["package_id"], 0), int(router["id"]))
                if package:
                    data = apply_package_to_voucher(data, package)
            error = validate_voucher(data)
            if error:
                flash(error, "danger")
                data["id"] = voucher_id
                return render_template("voucher_form.html", voucher=data, mode="edit", profile_names=profile_names, packages=packages_for_form)

            existing = get_voucher_by_username(data["username"], router["id"])
            if existing and existing["id"] != voucher_id:
                flash("Another local voucher on this router already uses this username.", "danger")
                data["id"] = voucher_id
                return render_template("voucher_form.html", voucher=data, mode="edit", profile_names=profile_names, packages=packages_for_form)

            try:
                data["routeros_id"] = RouterClient(active_router_settings(router)).update_voucher(
                    voucher["routeros_id"],
                    voucher["username"],
                    data,
                ) or voucher["routeros_id"]
                update_voucher_row(voucher_id, data, router["id"])
            except Exception as exc:
                flash(f"Could not update voucher on MikroTik router: {exc}", "danger")
                data["id"] = voucher_id
                return render_template("voucher_form.html", voucher=data, mode="edit", profile_names=profile_names, packages=packages_for_form)

            audit_log(current_user_id(), int(router["id"]), "voucher", voucher_id, "update", f"Voucher {data['username']} updated")
            flash("Voucher updated on the MikroTik router.", "success")
            return redirect(url_for("vouchers"))

        return render_template("voucher_form.html", voucher=voucher, mode="edit", profile_names=profile_names, packages=packages_for_form)

    @app.post("/vouchers/<int:voucher_id>/delete")
    def delete_voucher(voucher_id: int):
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))

        voucher = get_voucher(voucher_id, router["id"])
        if not voucher:
            flash("Voucher not found.", "warning")
            return redirect(url_for("vouchers"))

        try:
            remove_router_voucher_confirmed(
                RouterClient(active_router_settings(router)),
                voucher["routeros_id"],
                voucher["username"],
            )
            mark_voucher_deleted(voucher_id, router["id"])
            audit_log(current_user_id(), int(router["id"]), "voucher", voucher_id, "remove", f"Voucher {voucher['username']} removed")
        except Exception as exc:
            flash(f"Could not delete voucher from MikroTik router: {exc}", "danger")
            return redirect(url_for("vouchers"))

        flash("Voucher removed from the MikroTik router. Local history was kept.", "success")
        return redirect(url_for("vouchers"))

    @app.post("/vouchers/<int:voucher_id>/disable")
    def disable_voucher(voucher_id: int):
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))

        voucher = get_voucher(voucher_id, router["id"])
        if not voucher:
            flash("Voucher not found.", "warning")
            return redirect(url_for("vouchers"))

        try:
            RouterClient(active_router_settings(router)).disable_voucher(voucher["routeros_id"], voucher["username"])
            mark_voucher_disabled(voucher_id, router["id"])
            audit_log(current_user_id(), int(router["id"]), "voucher", voucher_id, "disable", f"Voucher {voucher['username']} disabled")
        except Exception as exc:
            flash(f"Could not disable voucher on MikroTik router: {exc}", "danger")
            return redirect(url_for("vouchers"))

        flash("Voucher disabled on the MikroTik router.", "success")
        return redirect(url_for("vouchers"))

    @app.post("/vouchers/<int:voucher_id>/renew")
    def renew_voucher(voucher_id: int):
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))

        flash("Renewing the same voucher code is disabled. Create a new voucher so used codes are never reused.", "warning")
        return redirect(url_for("vouchers"))

    @app.post("/vouchers/<int:voucher_id>/sell")
    def sell_voucher(voucher_id: int):
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))

        voucher = get_voucher(voucher_id, router["id"])
        if not voucher:
            flash("Voucher not found.", "warning")
            return redirect(url_for("vouchers"))
        try:
            record_sale(voucher_id, int(router["id"]), row_value(voucher, "price", "0.00"), request.form.get("payment_method", "Cash"))
            audit_log(current_user_id(), int(router["id"]), "sale", voucher_id, "create", f"Voucher {voucher['username']} sold")
            flash("Sale recorded.", "success")
        except Exception as exc:
            flash(f"Could not record sale: {exc}", "danger")
        return redirect(url_for("vouchers"))

    @app.route("/print")
    @app.route("/print/<int:voucher_id>")
    def print_vouchers(voucher_id: int | None = None):
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))

        if voucher_id:
            vouchers_to_print = [get_voucher(voucher_id, router["id"])]
        else:
            print_limit = print_voucher_limit()
            total = count_vouchers(router["id"])
            vouchers_to_print = list_vouchers(router["id"], limit=print_limit)
            if total > print_limit:
                flash(f"Showing the latest {print_limit} vouchers for printing. Print smaller batches for best speed.", "warning")
        vouchers_to_print = [voucher for voucher in vouchers_to_print if voucher]
        return render_template("print.html", vouchers=vouchers_to_print)

    @app.route("/manifest.json")
    def manifest():
        return app.send_static_file("manifest.json")

    @app.route("/service-worker.js")
    def service_worker():
        return app.send_static_file("service-worker.js")

    @app.cli.command("sync-vouchers")
    def sync_vouchers_command():
        summary = sync_all_routers()
        print(
            f"checked={summary['checked']} online={summary['online']} expired={summary['expired']} routers={summary['routers']}"
        )

    @app.cli.command("deployment-check")
    def deployment_check_command():
        errors = deployment_check_errors()
        if errors:
            for error in errors:
                click.echo(f"ERROR: {error}", err=True)
            raise click.ClickException(f"deployment check failed with {len(errors)} error(s)")
        click.echo("Deployment check passed.")

    return app


def load_secret_key() -> str:
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key

    if SECRET_KEY_PATH.exists():
        return SECRET_KEY_PATH.read_text(encoding="utf-8").strip()

    key = secrets.token_hex(32)
    SECRET_KEY_PATH.write_text(key, encoding="utf-8")
    return key


def secret_cipher():
    if Fernet is None:
        return None
    digest = hashlib.sha256(load_secret_key().encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(value: str) -> str:
    text = value or ""
    if not text or text.startswith("enc:"):
        return text
    cipher = secret_cipher()
    if cipher is None:
        raise RuntimeError("Karte requires cryptography so secrets are never stored as plaintext. Run: pip install -r requirements.txt")
    return "enc:" + cipher.encrypt(text.encode("utf-8")).decode("ascii")


def decrypt_secret(value: str) -> str:
    text = value or ""
    if not text.startswith("enc:"):
        return text
    cipher = secret_cipher()
    if cipher is None:
        raise RuntimeError("Encrypted router passwords need cryptography installed. Run: pip install -r requirements.txt")
    return cipher.decrypt(text[4:].encode("ascii")).decode("utf-8")


def is_production() -> bool:
    return os.environ.get("APP_ENV", "").strip().lower() in {"production", "prod"}


def env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def validate_startup_config() -> None:
    if Fernet is None:
        raise RuntimeError("Karte requires cryptography so router credentials are never stored as plaintext.")
    if not is_production():
        return

    errors = production_config_errors()
    if errors:
        raise RuntimeError("Production configuration error: " + " ".join(errors))


def production_config_errors() -> list[str]:
    errors = []
    secret_key = os.environ.get("SECRET_KEY", "").strip()
    placeholder_secret_keys = {
        "change-this-to-a-long-random-secret",
        "make-this-a-long-random-secret",
        "a-long-random-secret",
        "replace-with-a-long-random-secret-at-least-32-characters",
    }
    if len(secret_key) < 32 or secret_key in placeholder_secret_keys:
        errors.append("Set SECRET_KEY to a long random value.")

    if db_engine() != "mysql":
        errors.append("Set DB_ENGINE=mysql for VPS production.")

    if not env_flag("TRUST_PROXY", False):
        errors.append("Set TRUST_PROXY=1 when running behind Nginx.")

    if not env_flag("SESSION_COOKIE_SECURE", False):
        errors.append("Set SESSION_COOKIE_SECURE=1 and serve the app over HTTPS.")

    if env_flag("ENABLE_BACKGROUND_SYNC_IN_WEB", False):
        errors.append("Do not run voucher sync inside Gunicorn workers; use the Karte systemd sync timer.")

    required_mysql = ["MYSQL_HOST", "MYSQL_DATABASE", "MYSQL_USER", "MYSQL_PASSWORD"]
    for key in required_mysql:
        if not os.environ.get(key, "").strip():
            errors.append(f"Set {key}.")

    if os.environ.get("MYSQL_PASSWORD", "").strip() in {"change-this-password", "your_mysql_password"}:
        errors.append("Set MYSQL_PASSWORD to the real MySQL password.")

    if not os.environ.get("ROUTER_ALLOWED_NETWORKS", "").strip():
        errors.append("Set ROUTER_ALLOWED_NETWORKS explicitly; production must not use the broad development defaults.")
    if not allowed_router_networks():
        errors.append("Set ROUTER_ALLOWED_NETWORKS to the private WireGuard/LAN ranges used by your routers.")
    if not os.environ.get("ROUTER_ALLOWED_PORTS", "").strip():
        errors.append("Set ROUTER_ALLOWED_PORTS explicitly, normally to 8728,8729.")
    if not allowed_router_api_ports():
        errors.append("Set ROUTER_ALLOWED_PORTS to at least one valid RouterOS API port.")

    return errors


def deployment_check_errors() -> list[str]:
    errors = []
    if not is_production():
        errors.append("Set APP_ENV=production.")
    errors.extend(production_config_errors())

    try:
        purge_expired_router_sessions()
        with closing(get_db()) as db:
            active_admins = int(
                db.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1").fetchone()[0]
            )
            if active_admins < 1:
                errors.append("Create at least one active administrator account.")

            plaintext_checks = [
                ("routers", "router_password", "router credentials"),
                ("router_sessions", "router_password", "router session credentials"),
                ("wireguard_interfaces", "private_key", "WireGuard private keys"),
            ]
            for table, column, label in plaintext_checks:
                row = db.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE {column} <> '' AND {column} NOT LIKE 'enc:%'"
                ).fetchone()
                if int(row[0]):
                    errors.append(f"Encrypt all stored {label} before deployment.")

            if using_mysql():
                revision = db.execute("SELECT version_num FROM alembic_version LIMIT 1").fetchone()
                if not revision or row_value(revision, "version_num") != "20260723_02":
                    errors.append("Run `flask --app app db upgrade` to apply the latest database migration.")
    except Exception as exc:
        errors.append(f"Database readiness check failed: {exc}")

    return errors


def configure_http_settings(app: Flask) -> None:
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
    app.config["SESSION_COOKIE_SECURE"] = env_flag("SESSION_COOKIE_SECURE", is_production())

    if env_flag("TRUST_PROXY", is_production()):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)


def request_cached(name: str, factory):
    if not has_request_context():
        return factory()
    if not hasattr(g, name):
        setattr(g, name, factory())
    return getattr(g, name)


def clear_request_cache(*names: str) -> None:
    if not has_request_context():
        return
    for name in names:
        if hasattr(g, name):
            delattr(g, name)


def router_session_active() -> bool:
    def load_active_state() -> bool:
        router_session = get_router_session()
        if not router_session:
            return False
        if get_router(int(router_session["router_id"])):
            return True
        clear_router_session()
        return False

    return bool(request_cached("router_session_active", load_active_state))


def session_minutes_left() -> int:
    def load_minutes_left() -> int:
        router_session = get_router_session()
        if not router_session:
            return 0
        seconds_left = max(0, int(float(router_session["expires_at"]) - time.time()))
        return max(1, (seconds_left + 59) // 60)

    return int(request_cached("session_minutes_left", load_minutes_left))


def start_router_session(router_id: int, router) -> None:
    clear_router_session()
    purge_expired_router_sessions()
    user_id = current_user_id()
    if not user_id:
        raise RuntimeError("Login with a router IP before connecting a router.")

    token = secrets.token_urlsafe(32)
    expires_at = time.time() + ROUTER_SESSION_SECONDS
    now = timestamp()
    with closing(get_db()) as db:
        db.execute(
            """
            INSERT INTO router_sessions
                (token, user_id, router_id, router_ip, api_port, router_username, router_password, expires_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                token,
                user_id,
                int(router_id),
                row_value(router, "router_ip"),
                row_value(router, "api_port", "8728"),
                row_value(router, "router_username"),
                encrypt_secret(row_value(router, "router_password")),
                expires_at,
                now,
                now,
            ),
        )
        db.commit()

    session.permanent = True
    session["router_id"] = int(router_id)
    session["router_session_token"] = token
    clear_request_cache("router_session", "router_session_active", "active_router", "session_minutes_left")


def clear_router_session() -> None:
    token = session.get("router_session_token")
    if token:
        with closing(get_db()) as db:
            db.execute("DELETE FROM router_sessions WHERE token = ?", (token,))
            db.commit()

    for key in ["router_id", "router_session_token"]:
        session.pop(key, None)
    clear_request_cache("router_session", "router_session_active", "active_router", "session_minutes_left")


def get_router_session() -> sqlite3.Row | None:
    def load_router_session():
        token = session.get("router_session_token")
        user_id = current_user_id()
        if not token or not user_id:
            return None

        with closing(get_db()) as db:
            router_session = db.execute(
                "SELECT * FROM router_sessions WHERE token = ? AND user_id = ?",
                (token, user_id),
            ).fetchone()

            if not router_session:
                return None

            if float(router_session["expires_at"]) <= time.time():
                db.execute("DELETE FROM router_sessions WHERE token = ?", (token,))
                db.commit()
                return None

            return router_session

    return request_cached("router_session", load_router_session)


def purge_expired_router_sessions() -> int:
    with closing(get_db()) as db:
        cursor = db.execute("DELETE FROM router_sessions WHERE expires_at <= ?", (time.time(),))
        removed = int(getattr(cursor.cursor, "rowcount", 0)) if isinstance(cursor, MySqlCursor) else int(cursor.rowcount)
        db.commit()
    if removed:
        LOGGER.info("purged expired router sessions count=%s", removed)
    return removed


def safe_next_url(next_url: str | None) -> str | None:
    if next_url and next_url.startswith("/") and not next_url.startswith("//"):
        return next_url
    return None


def get_csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return str(token)


def current_user_id() -> int | None:
    user = current_user()
    return int(user["id"]) if user else None


def current_user():
    def load_current_user():
        if not has_request_context():
            return None
        user_id = parse_positive_int(session.get("user_id"), 0)
        if not user_id:
            return None
        user = get_user(user_id)
        if not user or not bool(int(row_value(user, "active", "0"))):
            return None
        data = dict(user)
        data["name"] = row_value(user, "username")
        data["is_admin"] = 1 if row_value(user, "role") == "admin" else 0
        return data

    return request_cached("current_user", load_current_user)


def app_user_session_active() -> bool:
    if not has_request_context():
        return False
    expires_at = float(session.get("auth_expires_at") or 0)
    if expires_at <= time.time():
        return False
    return current_user() is not None


def start_app_session(user) -> None:
    session.clear()
    session.permanent = True
    session["user_id"] = int(user["id"])
    session["auth_expires_at"] = time.time() + APP_SESSION_SECONDS
    clear_request_cache("current_user")
    get_csrf_token()


def clear_app_session() -> None:
    for key in ["user_id", "auth_expires_at"]:
        session.pop(key, None)
    clear_request_cache("current_user")


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user or row_value(user, "role") != "admin":
            flash("Administrator access is required.", "danger")
            return redirect(url_for("vouchers"))
        return view(*args, **kwargs)

    return wrapped


def user_count() -> int:
    with closing(get_db()) as db:
        return int(db.execute("SELECT COUNT(*) FROM users").fetchone()[0])


def get_user(user_id: int):
    with closing(get_db()) as db:
        return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_user_by_username(username: str):
    with closing(get_db()) as db:
        return db.execute(
            "SELECT * FROM users WHERE LOWER(username) = LOWER(?)",
            (username.strip(),),
        ).fetchone()


def list_users():
    with closing(get_db()) as db:
        return db.execute("SELECT * FROM users ORDER BY role, username").fetchall()


def active_admin_count() -> int:
    with closing(get_db()) as db:
        row = db.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1"
        ).fetchone()
    return int(row[0])


def user_from_form(existing=None, force_role: str = "") -> dict[str, str]:
    return {
        "username": request.form.get("username", row_value(existing, "username")).strip(),
        "password": request.form.get("password", ""),
        "role": force_role or request.form.get("role", row_value(existing, "role", "cashier")).strip().lower(),
        "active": "1" if force_role or request.form.get("active") == "1" else "0",
    }


def validate_user(user: dict[str, str], require_password: bool = False, existing_user_id: int = 0) -> str | None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", user.get("username", "")):
        return "Use a username with 3-64 letters, numbers, dots, hyphens, or underscores."
    if user.get("role") not in {"admin", "cashier"}:
        return "Choose Admin or Cashier."
    if require_password or user.get("password"):
        if len(user.get("password", "")) < 10:
            return "Use a password with at least 10 characters."
    existing = get_user_by_username(user["username"])
    if existing and int(existing["id"]) != int(existing_user_id or 0):
        return "That username is already in use."
    return None


def insert_user(user: dict[str, str]) -> int:
    now = timestamp()
    with closing(get_db()) as db:
        cursor = db.execute(
            """
            INSERT INTO users (username, password_hash, role, active, last_login_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, '', ?, ?)
            """,
            (
                user["username"],
                generate_password_hash(user["password"]),
                user["role"],
                1 if user.get("active") == "1" else 0,
                now,
                now,
            ),
        )
        db.commit()
        return int(cursor.lastrowid)


def update_user(user_id: int, user: dict[str, str]) -> None:
    with closing(get_db()) as db:
        if user.get("password"):
            db.execute(
                """
                UPDATE users
                SET username = ?, password_hash = ?, role = ?, active = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    user["username"],
                    generate_password_hash(user["password"]),
                    user["role"],
                    1 if user.get("active") == "1" else 0,
                    timestamp(),
                    user_id,
                ),
            )
        else:
            db.execute(
                """
                UPDATE users
                SET username = ?, role = ?, active = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    user["username"],
                    user["role"],
                    1 if user.get("active") == "1" else 0,
                    timestamp(),
                    user_id,
                ),
            )
        db.commit()


def update_user_last_login(user_id: int) -> None:
    with closing(get_db()) as db:
        db.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (timestamp(), user_id))
        db.commit()


def ensure_bootstrap_admin() -> None:
    if user_count() > 0:
        return
    password = os.environ.get("KARTE_ADMIN_PASSWORD", "")
    if not password:
        if is_production():
            raise RuntimeError("Set KARTE_ADMIN_PASSWORD to create the first administrator account.")
        return
    username = os.environ.get("KARTE_ADMIN_USERNAME", "admin").strip() or "admin"
    error = validate_user(
        {"username": username, "password": password, "role": "admin", "active": "1"},
        require_password=True,
    )
    if error:
        raise RuntimeError(f"Invalid bootstrap administrator configuration: {error}")
    insert_user({"username": username, "password": password, "role": "admin", "active": "1"})
    LOGGER.info("created bootstrap administrator username=%s", username)


def login_defaults(router_id: int = 0) -> dict[str, str]:
    router = get_authorized_router(router_id) if router_id else get_active_router()
    if router:
        data = router_to_safe_form_data(router)
        data["id"] = row_value(router, "id")
        return data

    return {
        "id": "",
        "name": "Router",
        "router_ip": "",
        "api_port": "8728",
        "router_username": "",
        "router_password": "",
    }


def login_attempt_client_key() -> str:
    address = request.remote_addr or "unknown"
    return hashlib.sha256(address.encode("utf-8")).hexdigest()


def login_rate_limit_settings() -> tuple[int, int]:
    try:
        maximum = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "5"))
    except ValueError:
        maximum = 5
    try:
        window = int(os.environ.get("LOGIN_WINDOW_SECONDS", "300"))
    except ValueError:
        window = 300
    return max(3, min(maximum, 20)), max(60, min(window, 3600))


def login_rate_limited(scope: str) -> bool:
    maximum, window = login_rate_limit_settings()
    cutoff = time.time() - window
    client_key = login_attempt_client_key()
    with closing(get_db()) as db:
        row = db.execute(
            """
            SELECT COUNT(*) AS attempt_count
            FROM router_login_attempts
            WHERE scope = ? AND client_key = ? AND attempted_at >= ? AND success = 0
            """,
            (scope, client_key, cutoff),
        ).fetchone()
    return parse_int(row_value(row, "attempt_count", "0")) >= maximum


def record_login_attempt(scope: str, success: bool) -> None:
    client_key = login_attempt_client_key()
    _, window = login_rate_limit_settings()
    with closing(get_db()) as db:
        db.execute("DELETE FROM router_login_attempts WHERE attempted_at < ?", (time.time() - (window * 2),))
        db.execute(
            "INSERT INTO router_login_attempts (scope, client_key, attempted_at, success) VALUES (?, ?, ?, ?)",
            (scope, client_key, time.time(), 1 if success else 0),
        )
        db.commit()


def clear_login_attempts(scope: str) -> None:
    with closing(get_db()) as db:
        db.execute(
            "DELETE FROM router_login_attempts WHERE scope = ? AND client_key = ?",
            (scope, login_attempt_client_key()),
        )
        db.commit()


def router_login_rate_limited() -> bool:
    return login_rate_limited("router")


def record_router_login_attempt(success: bool) -> None:
    record_login_attempt("router", success)


def clear_router_login_attempts() -> None:
    clear_login_attempts("router")


def save_login_router(router: dict[str, str]) -> int:
    existing = find_router_by_login(router)
    if existing:
        update_router(existing["id"], router)
        return int(existing["id"])
    return insert_router(router)


def load_env_file() -> None:
    path = BASE_DIR / ".env"
    if not path.exists():
        return

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def configure_logging() -> None:
    level_name = os.environ.get("LOG_LEVEL", "INFO").strip().upper() or "INFO"
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    LOGGER.setLevel(level)


def db_engine() -> str:
    engine = os.environ.get("DB_ENGINE", "").strip().lower()
    if engine:
        return engine
    if os.environ.get("MYSQL_HOST") or os.environ.get("MYSQL_DATABASE"):
        return "mysql"
    return "sqlite"


def using_mysql() -> bool:
    return db_engine() == "mysql"


class DbRow(dict):
    def __init__(self, columns: list[str], values: tuple):
        super().__init__(zip(columns, values))
        self._values = values

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)


class MySqlCursor:
    def __init__(self, cursor):
        self.cursor = cursor
        self.lastrowid = cursor.lastrowid
        self._columns = [column[0] for column in cursor.description or []]

    def fetchone(self):
        row = self.cursor.fetchone()
        if row is None:
            return None
        return DbRow(self._columns, row)

    def fetchall(self):
        return [DbRow(self._columns, row) for row in self.cursor.fetchall()]


class SqlAlchemyDb:
    def __init__(self):
        if pymysql is None or create_engine is None or URL is None:
            raise RuntimeError("MySQL needs SQLAlchemy and PyMySQL. Run: pip install -r requirements.txt")
        self.conn = mysql_connection()

    def execute(self, sql: str, params: tuple = ()):
        cursor = self.conn.cursor()
        cursor.execute(sql.replace("?", "%s"), params or ())
        return MySqlCursor(cursor)

    def commit(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


def is_database_integrity_error(exc: Exception) -> bool:
    if isinstance(exc, sqlite3.IntegrityError):
        return True
    mysql_integrity_error = pymysql.err.IntegrityError if pymysql else None
    return bool(mysql_integrity_error and isinstance(exc, mysql_integrity_error))


def mysql_config() -> dict[str, object]:
    return {
        "host": os.environ.get("MYSQL_HOST", "127.0.0.1"),
        "port": int(os.environ.get("MYSQL_PORT", "3306")),
        "user": os.environ.get("MYSQL_USER", "voucher_app"),
        "password": os.environ.get("MYSQL_PASSWORD", ""),
        "database": os.environ.get("MYSQL_DATABASE", "mikrotik_vouchers"),
        "charset": "utf8mb4",
        "autocommit": False,
    }


def mysql_pool_size() -> int:
    raw = os.environ.get("MYSQL_POOL_SIZE", "10").strip()
    try:
        size = int(raw)
    except ValueError:
        size = 10
    return max(1, min(size, 32))


def create_mysql_database_if_missing(config: dict[str, object]) -> None:
    database = str(config.get("database") or "")
    if not database:
        return

    bootstrap_config = dict(config)
    bootstrap_config.pop("database", None)
    bootstrap_config.pop("autocommit", None)
    with closing(pymysql.connect(**bootstrap_config)) as conn:
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {mysql_identifier(database)} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        conn.commit()


def mysql_connection():
    return sqlalchemy_mysql_engine().raw_connection()


def sqlalchemy_mysql_engine():
    global MYSQL_ENGINE
    config = mysql_config()
    if MYSQL_ENGINE is not None:
        return MYSQL_ENGINE

    url = URL.create(
        "mysql+pymysql",
        username=str(config["user"]),
        password=str(config["password"]),
        host=str(config["host"]),
        port=int(config["port"]),
        database=str(config["database"]),
        query={"charset": "utf8mb4"},
    )
    engine = create_engine(
        url,
        pool_size=mysql_pool_size(),
        max_overflow=max(2, mysql_pool_size()),
        pool_pre_ping=True,
        pool_recycle=1800,
    )
    try:
        connection = engine.raw_connection()
        connection.close()
    except Exception as exc:
        error_code = exc.args[0] if getattr(exc, "args", None) else None
        original = getattr(exc, "orig", None)
        if original is not None and getattr(original, "args", None):
            error_code = original.args[0]
        if error_code != 1049:
            engine.dispose()
            raise
        engine.dispose()
        create_mysql_database_if_missing(config)
        engine = create_engine(
            url,
            pool_size=mysql_pool_size(),
            max_overflow=max(2, mysql_pool_size()),
            pool_pre_ping=True,
            pool_recycle=1800,
        )
    MYSQL_ENGINE = engine
    return MYSQL_ENGINE


def mysql_identifier(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_]+", name):
        raise RuntimeError("MYSQL_DATABASE may only contain letters, numbers, and underscores.")
    return f"`{name}`"


def get_db():
    if using_mysql():
        return SqlAlchemyDb()

    database = Path(os.environ.get("SQLITE_DATABASE_PATH", str(DATABASE))).expanduser()
    database.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row
    return conn


def run_alembic_migrations() -> None:
    try:
        from alembic import command
        from alembic.config import Config
    except ImportError as exc:
        raise RuntimeError("MySQL schema migrations need Alembic. Run: pip install -r requirements.txt") from exc

    config = Config(str(BASE_DIR / "alembic.ini"))
    with sqlalchemy_mysql_engine().begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")


def init_db() -> None:
    with closing(get_db()) as db:
        if using_mysql():
            lock = db.execute("SELECT GET_LOCK(?, ?) AS acquired", ("karte_schema_init", 30)).fetchone()
            if row_value(lock, "acquired", "0") != "1":
                raise RuntimeError("Could not acquire the database schema lock.")
            try:
                run_alembic_migrations()
                migrate_wireguard_secrets(db)
                migrate_legacy_secret_storage(db)
                db.commit()
            finally:
                db.execute("SELECT RELEASE_LOCK(?)", ("karte_schema_init",)).fetchone()
            return

        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS settings (
                `key` TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'cashier',
                active INTEGER NOT NULL DEFAULT 1,
                last_login_at TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS routers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                router_ip TEXT NOT NULL,
                api_port TEXT NOT NULL DEFAULT '8728',
                router_username TEXT NOT NULL,
                router_password TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'unknown',
                last_synced_at TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vouchers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                router_id INTEGER,
                package_id INTEGER,
                batch_id INTEGER,
                created_by INTEGER,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                profile TEXT NOT NULL,
                time_limit TEXT NOT NULL,
                price NUMERIC NOT NULL DEFAULT 0.00,
                data_limit TEXT NOT NULL DEFAULT '',
                shared_users TEXT NOT NULL DEFAULT '1',
                status TEXT NOT NULL DEFAULT 'unused',
                `comment` TEXT NOT NULL DEFAULT '',
                expiry_date TEXT NOT NULL DEFAULT '',
                activated_at TEXT NOT NULL DEFAULT '',
                expires_at TEXT NOT NULL DEFAULT '',
                removed_at TEXT NOT NULL DEFAULT '',
                last_error TEXT NOT NULL DEFAULT '',
                retry_count INTEGER NOT NULL DEFAULT 0,
                first_login_mac TEXT NOT NULL DEFAULT '',
                first_login_ip TEXT NOT NULL DEFAULT '',
                device_name TEXT NOT NULL DEFAULT '',
                uptime_used TEXT NOT NULL DEFAULT '',
                data_used TEXT NOT NULL DEFAULT '',
                online_users INTEGER NOT NULL DEFAULT 0,
                routeros_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (router_id) REFERENCES routers(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS packages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                router_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                rate_limit TEXT NOT NULL DEFAULT '',
                validity_period TEXT NOT NULL,
                data_cap TEXT NOT NULL DEFAULT '',
                price NUMERIC NOT NULL DEFAULT 0.00,
                archived INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (router_id) REFERENCES routers(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS voucher_batches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                router_id INTEGER NOT NULL,
                prefix TEXT NOT NULL DEFAULT '',
                character_set TEXT NOT NULL DEFAULT 'uppercase_numbers',
                avoid_ambiguous INTEGER NOT NULL DEFAULT 1,
                quantity INTEGER NOT NULL,
                package_id INTEGER,
                created_by INTEGER,
                pushed_count INTEGER NOT NULL DEFAULT 0,
                failed_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (router_id) REFERENCES routers(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS sales (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                voucher_id INTEGER NOT NULL,
                cashier_id INTEGER,
                amount NUMERIC NOT NULL DEFAULT 0.00,
                payment_method TEXT NOT NULL DEFAULT 'Cash',
                timestamp TEXT NOT NULL,
                FOREIGN KEY (voucher_id) REFERENCES vouchers(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_user_id INTEGER,
                router_id INTEGER,
                entity_type TEXT NOT NULL,
                entity_id INTEGER,
                action TEXT NOT NULL,
                message TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS reconciliation_issues (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                router_id INTEGER NOT NULL,
                issue_type TEXT NOT NULL,
                remote_name TEXT NOT NULL,
                routeros_id TEXT NOT NULL DEFAULT '',
                details TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open',
                occurrence_count INTEGER NOT NULL DEFAULT 1,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                resolved_at TEXT NOT NULL DEFAULT '',
                FOREIGN KEY (router_id) REFERENCES routers(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS wireguard_interfaces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                interface_name TEXT NOT NULL,
                private_key TEXT NOT NULL,
                public_key TEXT NOT NULL,
                listen_port INTEGER NOT NULL DEFAULT 51820,
                address TEXT NOT NULL,
                mtu INTEGER NOT NULL DEFAULT 1420,
                notes TEXT,
                router_id INTEGER,
                created_at TEXT NOT NULL,
                FOREIGN KEY (router_id) REFERENCES routers(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS router_sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER,
                router_id INTEGER NOT NULL,
                router_ip TEXT NOT NULL,
                api_port TEXT NOT NULL,
                router_username TEXT NOT NULL,
                router_password TEXT NOT NULL,
                expires_at REAL NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (router_id) REFERENCES routers(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS router_login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope TEXT NOT NULL DEFAULT 'router',
                client_key TEXT NOT NULL,
                attempted_at REAL NOT NULL,
                success INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        migrate_router_status_schema(db)
        migrate_user_schema(db)
        migrate_legacy_router(db)
        migrate_vouchers_schema(db)
        migrate_voucher_details_schema(db)
        migrate_voucher_lifecycle_schema(db)
        migrate_package_schema(db)
        migrate_reconciliation_schema(db)
        migrate_wireguard_schema(db)
        migrate_wireguard_secrets(db)
        migrate_legacy_secret_storage(db)
        migrate_login_attempt_schema(db)
        assert_unique_voucher_data(db)
        db.execute("CREATE INDEX IF NOT EXISTS idx_vouchers_router_id ON vouchers(router_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_vouchers_status ON vouchers(status)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_vouchers_created_at ON vouchers(created_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_vouchers_price ON vouchers(price)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_vouchers_plan_name ON vouchers(profile)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_vouchers_router_created_id ON vouchers(router_id, created_at, id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_vouchers_router_status_created_id ON vouchers(router_id, status, created_at, id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_vouchers_router_username ON vouchers(router_id, username)")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_vouchers_router_username ON vouchers(router_id, username)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_vouchers_router_status_id ON vouchers(router_id, status, id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_vouchers_router_profile_created_id ON vouchers(router_id, profile, created_at, id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_vouchers_router_expiry_id ON vouchers(router_id, expiry_date, id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_vouchers_package_id ON vouchers(package_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_vouchers_router_package_status ON vouchers(router_id, package_id, status)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_vouchers_batch_id ON vouchers(batch_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_vouchers_expires_at ON vouchers(expires_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_vouchers_router_status_expires ON vouchers(router_id, status, expires_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_routers_login ON routers(router_ip, api_port, router_username, id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_routers_name_id ON routers(name, id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_packages_router_archived ON packages(router_id, archived)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_packages_router_name ON packages(router_id, name)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_batches_router_created ON voucher_batches(router_id, created_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_batches_package_created ON voucher_batches(package_id, created_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_sales_timestamp ON sales(timestamp)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_sales_cashier_timestamp ON sales(cashier_id, timestamp)")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_sales_voucher_id ON sales(voucher_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_audit_router_created ON audit_logs(router_id, created_at)")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_reconciliation_issue_key ON reconciliation_issues(router_id, issue_type, remote_name)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_reconciliation_router_status ON reconciliation_issues(router_id, status, last_seen_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_router_sessions_user_id ON router_sessions(user_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_router_sessions_expires_at ON router_sessions(expires_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_router_sessions_user_expires ON router_sessions(user_id, expires_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_router_login_attempts_scope_client_time ON router_login_attempts(scope, client_key, attempted_at)")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_username ON users(username)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_users_role_active ON users(role, active)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_wireguard_interface_name ON wireguard_interfaces(interface_name)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_wireguard_created_at ON wireguard_interfaces(created_at)")
        db.commit()


def init_mysql_db(db) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS settings (
            `key` VARCHAR(191) PRIMARY KEY,
            value TEXT NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INT PRIMARY KEY AUTO_INCREMENT,
            username VARCHAR(191) NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(32) NOT NULL DEFAULT 'cashier',
            active TINYINT NOT NULL DEFAULT 1,
            last_login_at VARCHAR(19) NOT NULL DEFAULT '',
            created_at VARCHAR(19) NOT NULL,
            updated_at VARCHAR(19) NOT NULL,
            UNIQUE KEY ux_users_username (username),
            INDEX idx_users_role_active (role, active)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS routers (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(191) NOT NULL,
            router_ip VARCHAR(191) NOT NULL,
            api_port VARCHAR(20) NOT NULL DEFAULT '8728',
            router_username VARCHAR(191) NOT NULL,
            router_password TEXT NOT NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'unknown',
            last_synced_at VARCHAR(19) NOT NULL DEFAULT '',
            created_at VARCHAR(19) NOT NULL,
            updated_at VARCHAR(19) NOT NULL,
            INDEX idx_routers_login (router_ip, api_port, router_username),
            INDEX idx_routers_name_id (name, id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS vouchers (
            id INT PRIMARY KEY AUTO_INCREMENT,
            router_id INT NULL,
            package_id INT NULL,
            batch_id INT NULL,
            created_by INT NULL,
            username VARCHAR(191) NOT NULL,
            password TEXT NOT NULL,
            profile VARCHAR(191) NOT NULL,
            time_limit VARCHAR(64) NOT NULL,
            price DECIMAL(10,2) NOT NULL DEFAULT 0.00,
            data_limit VARCHAR(64) NOT NULL DEFAULT '',
            shared_users VARCHAR(16) NOT NULL DEFAULT '1',
            status VARCHAR(32) NOT NULL DEFAULT 'unused',
            `comment` TEXT,
            expiry_date VARCHAR(32) NOT NULL DEFAULT '',
            activated_at VARCHAR(19) NOT NULL DEFAULT '',
            expires_at VARCHAR(19) NOT NULL DEFAULT '',
            removed_at VARCHAR(19) NOT NULL DEFAULT '',
            last_error TEXT,
            retry_count INT NOT NULL DEFAULT 0,
            first_login_mac VARCHAR(64) NOT NULL DEFAULT '',
            first_login_ip VARCHAR(64) NOT NULL DEFAULT '',
            device_name VARCHAR(191) NOT NULL DEFAULT '',
            uptime_used VARCHAR(64) NOT NULL DEFAULT '',
            data_used VARCHAR(64) NOT NULL DEFAULT '',
            online_users INT NOT NULL DEFAULT 0,
            routeros_id VARCHAR(191),
            created_at VARCHAR(19) NOT NULL,
            updated_at VARCHAR(19) NOT NULL,
            INDEX idx_vouchers_router_id (router_id),
            INDEX idx_vouchers_status (status),
            INDEX idx_vouchers_created_at (created_at),
            INDEX idx_vouchers_price (price),
            INDEX idx_vouchers_plan_name (profile),
            INDEX idx_vouchers_router_created_id (router_id, created_at, id),
            INDEX idx_vouchers_router_status_created_id (router_id, status, created_at, id),
            INDEX idx_vouchers_router_username (router_id, username),
            INDEX idx_vouchers_router_status_id (router_id, status, id),
            INDEX idx_vouchers_package_id (package_id),
            INDEX idx_vouchers_batch_id (batch_id),
            INDEX idx_vouchers_expires_at (expires_at),
            INDEX idx_vouchers_router_status_expires (router_id, status, expires_at),
            CONSTRAINT fk_vouchers_router
                FOREIGN KEY (router_id) REFERENCES routers(id)
                ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS packages (
            id INT PRIMARY KEY AUTO_INCREMENT,
            router_id INT NOT NULL,
            name VARCHAR(191) NOT NULL,
            rate_limit VARCHAR(100) NOT NULL DEFAULT '',
            validity_period VARCHAR(64) NOT NULL,
            data_cap VARCHAR(64) NOT NULL DEFAULT '',
            price DECIMAL(10,2) NOT NULL DEFAULT 0.00,
            archived TINYINT NOT NULL DEFAULT 0,
            created_at VARCHAR(19) NOT NULL,
            updated_at VARCHAR(19) NOT NULL,
            INDEX idx_packages_router_archived (router_id, archived),
            INDEX idx_packages_router_name (router_id, name),
            CONSTRAINT fk_packages_router
                FOREIGN KEY (router_id) REFERENCES routers(id)
                ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS voucher_batches (
            id INT PRIMARY KEY AUTO_INCREMENT,
            router_id INT NOT NULL,
            prefix VARCHAR(32) NOT NULL DEFAULT '',
            character_set VARCHAR(32) NOT NULL DEFAULT 'uppercase_numbers',
            avoid_ambiguous TINYINT NOT NULL DEFAULT 1,
            quantity INT NOT NULL,
            package_id INT NULL,
            created_by INT NULL,
            pushed_count INT NOT NULL DEFAULT 0,
            failed_count INT NOT NULL DEFAULT 0,
            created_at VARCHAR(19) NOT NULL,
            INDEX idx_batches_router_created (router_id, created_at),
            INDEX idx_batches_package_created (package_id, created_at),
            CONSTRAINT fk_batches_router
                FOREIGN KEY (router_id) REFERENCES routers(id)
                ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS sales (
            id INT PRIMARY KEY AUTO_INCREMENT,
            voucher_id INT NOT NULL,
            cashier_id INT NULL,
            amount DECIMAL(10,2) NOT NULL DEFAULT 0.00,
            payment_method VARCHAR(64) NOT NULL DEFAULT 'Cash',
            timestamp VARCHAR(19) NOT NULL,
            INDEX idx_sales_timestamp (timestamp),
            INDEX idx_sales_cashier_timestamp (cashier_id, timestamp),
            CONSTRAINT fk_sales_voucher
                FOREIGN KEY (voucher_id) REFERENCES vouchers(id)
                ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INT PRIMARY KEY AUTO_INCREMENT,
            actor_user_id INT NULL,
            router_id INT NULL,
            entity_type VARCHAR(64) NOT NULL,
            entity_id INT NULL,
            action VARCHAR(64) NOT NULL,
            message TEXT,
            created_at VARCHAR(19) NOT NULL,
            INDEX idx_audit_router_created (router_id, created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS reconciliation_issues (
            id INT PRIMARY KEY AUTO_INCREMENT,
            router_id INT NOT NULL,
            issue_type VARCHAR(64) NOT NULL,
            remote_name VARCHAR(191) NOT NULL,
            routeros_id VARCHAR(191) NOT NULL DEFAULT '',
            details TEXT,
            status VARCHAR(32) NOT NULL DEFAULT 'open',
            occurrence_count INT NOT NULL DEFAULT 1,
            first_seen_at VARCHAR(19) NOT NULL,
            last_seen_at VARCHAR(19) NOT NULL,
            resolved_at VARCHAR(19) NOT NULL DEFAULT '',
            UNIQUE KEY ux_reconciliation_issue_key (router_id, issue_type, remote_name),
            INDEX idx_reconciliation_router_status (router_id, status, last_seen_at),
            CONSTRAINT fk_reconciliation_router
                FOREIGN KEY (router_id) REFERENCES routers(id)
                ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS wireguard_interfaces (
            id INT PRIMARY KEY AUTO_INCREMENT,
            interface_name VARCHAR(100) NOT NULL,
            private_key TEXT NOT NULL,
            public_key TEXT NOT NULL,
            listen_port INT NOT NULL DEFAULT 51820,
            address VARCHAR(100) NOT NULL,
            mtu INT NOT NULL DEFAULT 1420,
            notes TEXT NULL,
            router_id INT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_wireguard_interface_name (interface_name),
            INDEX idx_wireguard_created_at (created_at),
            CONSTRAINT fk_wireguard_router
                FOREIGN KEY (router_id) REFERENCES routers(id)
                ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS router_sessions (
            token VARCHAR(191) PRIMARY KEY,
            user_id INT NULL,
            router_id INT NOT NULL,
            router_ip VARCHAR(191) NOT NULL,
            api_port VARCHAR(20) NOT NULL,
            router_username VARCHAR(191) NOT NULL,
            router_password TEXT NOT NULL,
            expires_at DOUBLE NOT NULL,
            created_at VARCHAR(19) NOT NULL,
            updated_at VARCHAR(19) NOT NULL,
            INDEX idx_router_sessions_user_id (user_id),
            INDEX idx_router_sessions_expires_at (expires_at),
            INDEX idx_router_sessions_user_expires (user_id, expires_at),
            CONSTRAINT fk_router_sessions_router
                FOREIGN KEY (router_id) REFERENCES routers(id)
                ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS router_login_attempts (
            id BIGINT PRIMARY KEY AUTO_INCREMENT,
            scope VARCHAR(32) NOT NULL DEFAULT 'router',
            client_key CHAR(64) NOT NULL,
            attempted_at DOUBLE NOT NULL,
            success TINYINT NOT NULL DEFAULT 0,
            INDEX idx_router_login_attempts_scope_client_time (scope, client_key, attempted_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    migrate_mysql_router_status_schema(db)
    migrate_mysql_user_schema(db)
    migrate_mysql_voucher_details_schema(db)
    migrate_mysql_voucher_lifecycle_schema(db)
    migrate_mysql_package_schema(db)
    migrate_mysql_reconciliation_schema(db)
    migrate_mysql_wireguard_schema(db)
    migrate_wireguard_secrets(db)
    migrate_legacy_secret_storage(db)
    assert_unique_voucher_data(db)
    ensure_mysql_indexes(db)
    ensure_mysql_unique_indexes(db)


def migrate_router_status_schema(db: sqlite3.Connection) -> None:
    columns = table_columns(db, "routers")
    new_columns = {
        "status": "TEXT NOT NULL DEFAULT 'unknown'",
        "last_synced_at": "TEXT NOT NULL DEFAULT ''",
    }
    for name, definition in new_columns.items():
        if name not in columns:
            db.execute(f"ALTER TABLE routers ADD COLUMN `{name}` {definition}")


def migrate_user_schema(db: sqlite3.Connection) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'cashier',
            active INTEGER NOT NULL DEFAULT 1,
            last_login_at TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )


def migrate_mysql_user_schema(db) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INT PRIMARY KEY AUTO_INCREMENT,
            username VARCHAR(191) NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(32) NOT NULL DEFAULT 'cashier',
            active TINYINT NOT NULL DEFAULT 1,
            last_login_at VARCHAR(19) NOT NULL DEFAULT '',
            created_at VARCHAR(19) NOT NULL,
            updated_at VARCHAR(19) NOT NULL,
            UNIQUE KEY ux_users_username (username),
            INDEX idx_users_role_active (role, active)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )


def migrate_mysql_router_status_schema(db) -> None:
    columns = mysql_table_columns(db, "routers")
    new_columns = {
        "status": "VARCHAR(32) NOT NULL DEFAULT 'unknown'",
        "last_synced_at": "VARCHAR(19) NOT NULL DEFAULT ''",
    }
    for name, definition in new_columns.items():
        if name not in columns:
            db.execute(f"ALTER TABLE routers ADD COLUMN `{name}` {definition}")


def ensure_mysql_indexes(db) -> None:
    indexes = [
        ("vouchers", "idx_vouchers_status", "status"),
        ("vouchers", "idx_vouchers_created_at", "created_at"),
        ("vouchers", "idx_vouchers_price", "price"),
        ("vouchers", "idx_vouchers_plan_name", "profile"),
        ("vouchers", "idx_vouchers_router_created_id", "router_id, created_at, id"),
        ("vouchers", "idx_vouchers_router_status_created_id", "router_id, status, created_at, id"),
        ("vouchers", "idx_vouchers_router_username", "router_id, username"),
        ("vouchers", "idx_vouchers_router_status_id", "router_id, status, id"),
        ("vouchers", "idx_vouchers_router_profile_created_id", "router_id, profile, created_at, id"),
        ("vouchers", "idx_vouchers_router_expiry_id", "router_id, expiry_date, id"),
        ("vouchers", "idx_vouchers_package_id", "package_id"),
        ("vouchers", "idx_vouchers_router_package_status", "router_id, package_id, status"),
        ("vouchers", "idx_vouchers_batch_id", "batch_id"),
        ("vouchers", "idx_vouchers_expires_at", "expires_at"),
        ("vouchers", "idx_vouchers_router_status_expires", "router_id, status, expires_at"),
        ("routers", "idx_routers_login_id", "router_ip, api_port, router_username, id"),
        ("routers", "idx_routers_name_id", "name, id"),
        ("packages", "idx_packages_router_archived", "router_id, archived"),
        ("packages", "idx_packages_router_name", "router_id, name"),
        ("voucher_batches", "idx_batches_router_created", "router_id, created_at"),
        ("voucher_batches", "idx_batches_package_created", "package_id, created_at"),
        ("sales", "idx_sales_timestamp", "timestamp"),
        ("sales", "idx_sales_cashier_timestamp", "cashier_id, timestamp"),
        ("audit_logs", "idx_audit_router_created", "router_id, created_at"),
        ("router_sessions", "idx_router_sessions_user_expires", "user_id, expires_at"),
        ("router_login_attempts", "idx_router_login_attempts_scope_client_time", "scope, client_key, attempted_at"),
        ("wireguard_interfaces", "idx_wireguard_interface_name", "interface_name"),
        ("wireguard_interfaces", "idx_wireguard_created_at", "created_at"),
    ]
    for table, index_name, columns in indexes:
        if not mysql_index_exists(db, table, index_name):
            db.execute(f"CREATE INDEX {mysql_identifier(index_name)} ON {mysql_identifier(table)} ({columns})")


def ensure_mysql_unique_indexes(db) -> None:
    indexes = [
        ("vouchers", "ux_vouchers_router_username", "router_id, username"),
        ("sales", "ux_sales_voucher_id", "voucher_id"),
    ]
    for table, index_name, columns in indexes:
        if not mysql_index_exists(db, table, index_name):
            db.execute(f"CREATE UNIQUE INDEX {mysql_identifier(index_name)} ON {mysql_identifier(table)} ({columns})")


def assert_unique_voucher_data(db) -> None:
    duplicate_voucher = db.execute(
        """
        SELECT router_id, username, COUNT(*) AS duplicate_count
        FROM vouchers
        WHERE router_id IS NOT NULL
        GROUP BY router_id, username
        HAVING COUNT(*) > 1
        LIMIT 1
        """
    ).fetchone()
    if duplicate_voucher:
        raise RuntimeError(
            "Duplicate voucher codes already exist for one router. Resolve them before starting Karte: "
            f"router_id={row_value(duplicate_voucher, 'router_id')} username={row_value(duplicate_voucher, 'username')}."
        )

    duplicate_sale = db.execute(
        """
        SELECT voucher_id, COUNT(*) AS duplicate_count
        FROM sales
        GROUP BY voucher_id
        HAVING COUNT(*) > 1
        LIMIT 1
        """
    ).fetchone()
    if duplicate_sale:
        raise RuntimeError(
            "Duplicate sales already exist for a voucher. Resolve them before starting Karte: "
            f"voucher_id={row_value(duplicate_sale, 'voucher_id')}."
        )


def mysql_index_exists(db, table: str, index_name: str) -> bool:
    rows = db.execute(
        f"SHOW INDEX FROM {mysql_identifier(table)} WHERE Key_name = ?",
        (index_name,),
    ).fetchall()
    return bool(rows)


def migrate_voucher_details_schema(db: sqlite3.Connection) -> None:
    columns = table_columns(db, "vouchers")
    new_columns = {
        "price": "NUMERIC NOT NULL DEFAULT 0.00",
        "data_limit": "TEXT NOT NULL DEFAULT ''",
        "shared_users": "TEXT NOT NULL DEFAULT '1'",
        "status": "TEXT NOT NULL DEFAULT 'unused'",
        "comment": "TEXT NOT NULL DEFAULT ''",
        "expiry_date": "TEXT NOT NULL DEFAULT ''",
        "activated_at": "TEXT NOT NULL DEFAULT ''",
        "first_login_mac": "TEXT NOT NULL DEFAULT ''",
        "first_login_ip": "TEXT NOT NULL DEFAULT ''",
        "device_name": "TEXT NOT NULL DEFAULT ''",
        "uptime_used": "TEXT NOT NULL DEFAULT ''",
        "data_used": "TEXT NOT NULL DEFAULT ''",
        "online_users": "INTEGER NOT NULL DEFAULT 0",
    }

    for name, definition in new_columns.items():
        if name not in columns:
            db.execute(f"ALTER TABLE vouchers ADD COLUMN `{name}` {definition}")


def migrate_mysql_voucher_details_schema(db) -> None:
    columns = mysql_table_columns(db, "vouchers")
    new_columns = {
        "price": "DECIMAL(10,2) NOT NULL DEFAULT 0.00",
        "data_limit": "VARCHAR(64) NOT NULL DEFAULT ''",
        "shared_users": "VARCHAR(16) NOT NULL DEFAULT '1'",
        "status": "VARCHAR(32) NOT NULL DEFAULT 'unused'",
        "comment": "TEXT",
        "expiry_date": "VARCHAR(32) NOT NULL DEFAULT ''",
        "activated_at": "VARCHAR(19) NOT NULL DEFAULT ''",
        "first_login_mac": "VARCHAR(64) NOT NULL DEFAULT ''",
        "first_login_ip": "VARCHAR(64) NOT NULL DEFAULT ''",
        "device_name": "VARCHAR(191) NOT NULL DEFAULT ''",
        "uptime_used": "VARCHAR(64) NOT NULL DEFAULT ''",
        "data_used": "VARCHAR(64) NOT NULL DEFAULT ''",
        "online_users": "INT NOT NULL DEFAULT 0",
    }

    for name, definition in new_columns.items():
        if name not in columns:
            db.execute(f"ALTER TABLE vouchers ADD COLUMN `{name}` {definition}")


def migrate_voucher_lifecycle_schema(db: sqlite3.Connection) -> None:
    columns = table_columns(db, "vouchers")
    new_columns = {
        "package_id": "INTEGER",
        "batch_id": "INTEGER",
        "created_by": "INTEGER",
        "expires_at": "TEXT NOT NULL DEFAULT ''",
        "removed_at": "TEXT NOT NULL DEFAULT ''",
        "last_error": "TEXT NOT NULL DEFAULT ''",
        "retry_count": "INTEGER NOT NULL DEFAULT 0",
    }
    for name, definition in new_columns.items():
        if name not in columns:
            db.execute(f"ALTER TABLE vouchers ADD COLUMN `{name}` {definition}")


def migrate_mysql_voucher_lifecycle_schema(db) -> None:
    columns = mysql_table_columns(db, "vouchers")
    new_columns = {
        "package_id": "INT NULL",
        "batch_id": "INT NULL",
        "created_by": "INT NULL",
        "expires_at": "VARCHAR(19) NOT NULL DEFAULT ''",
        "removed_at": "VARCHAR(19) NOT NULL DEFAULT ''",
        "last_error": "TEXT",
        "retry_count": "INT NOT NULL DEFAULT 0",
    }
    for name, definition in new_columns.items():
        if name not in columns:
            db.execute(f"ALTER TABLE vouchers ADD COLUMN `{name}` {definition}")


def migrate_reconciliation_schema(db: sqlite3.Connection) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS reconciliation_issues (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            router_id INTEGER NOT NULL,
            issue_type TEXT NOT NULL,
            remote_name TEXT NOT NULL,
            routeros_id TEXT NOT NULL DEFAULT '',
            details TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open',
            occurrence_count INTEGER NOT NULL DEFAULT 1,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            resolved_at TEXT NOT NULL DEFAULT '',
            FOREIGN KEY (router_id) REFERENCES routers(id) ON DELETE CASCADE
        )
        """
    )


def migrate_mysql_reconciliation_schema(db) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS reconciliation_issues (
            id INT PRIMARY KEY AUTO_INCREMENT,
            router_id INT NOT NULL,
            issue_type VARCHAR(64) NOT NULL,
            remote_name VARCHAR(191) NOT NULL,
            routeros_id VARCHAR(191) NOT NULL DEFAULT '',
            details TEXT,
            status VARCHAR(32) NOT NULL DEFAULT 'open',
            occurrence_count INT NOT NULL DEFAULT 1,
            first_seen_at VARCHAR(19) NOT NULL,
            last_seen_at VARCHAR(19) NOT NULL,
            resolved_at VARCHAR(19) NOT NULL DEFAULT '',
            UNIQUE KEY ux_reconciliation_issue_key (router_id, issue_type, remote_name),
            INDEX idx_reconciliation_router_status (router_id, status, last_seen_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )


def migrate_package_schema(db: sqlite3.Connection) -> None:
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            router_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            rate_limit TEXT NOT NULL DEFAULT '',
            validity_period TEXT NOT NULL,
            data_cap TEXT NOT NULL DEFAULT '',
            price NUMERIC NOT NULL DEFAULT 0.00,
            archived INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (router_id) REFERENCES routers(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS voucher_batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            router_id INTEGER NOT NULL,
            prefix TEXT NOT NULL DEFAULT '',
            character_set TEXT NOT NULL DEFAULT 'uppercase_numbers',
            avoid_ambiguous INTEGER NOT NULL DEFAULT 1,
            quantity INTEGER NOT NULL,
            package_id INTEGER,
            created_by INTEGER,
            pushed_count INTEGER NOT NULL DEFAULT 0,
            failed_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (router_id) REFERENCES routers(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            voucher_id INTEGER NOT NULL,
            cashier_id INTEGER,
            amount NUMERIC NOT NULL DEFAULT 0.00,
            payment_method TEXT NOT NULL DEFAULT 'Cash',
            timestamp TEXT NOT NULL,
            FOREIGN KEY (voucher_id) REFERENCES vouchers(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id INTEGER,
            router_id INTEGER,
            entity_type TEXT NOT NULL,
            entity_id INTEGER,
            action TEXT NOT NULL,
            message TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        """
    )
    batch_columns = table_columns(db, "voucher_batches")
    for name, definition in {
        "character_set": "TEXT NOT NULL DEFAULT 'uppercase_numbers'",
        "avoid_ambiguous": "INTEGER NOT NULL DEFAULT 1",
    }.items():
        if name not in batch_columns:
            db.execute(f"ALTER TABLE voucher_batches ADD COLUMN `{name}` {definition}")


def migrate_mysql_package_schema(db) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS packages (
            id INT PRIMARY KEY AUTO_INCREMENT,
            router_id INT NOT NULL,
            name VARCHAR(191) NOT NULL,
            rate_limit VARCHAR(100) NOT NULL DEFAULT '',
            validity_period VARCHAR(64) NOT NULL,
            data_cap VARCHAR(64) NOT NULL DEFAULT '',
            price DECIMAL(10,2) NOT NULL DEFAULT 0.00,
            archived TINYINT NOT NULL DEFAULT 0,
            created_at VARCHAR(19) NOT NULL,
            updated_at VARCHAR(19) NOT NULL,
            INDEX idx_packages_router_archived (router_id, archived),
            INDEX idx_packages_router_name (router_id, name)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS voucher_batches (
            id INT PRIMARY KEY AUTO_INCREMENT,
            router_id INT NOT NULL,
            prefix VARCHAR(32) NOT NULL DEFAULT '',
            character_set VARCHAR(32) NOT NULL DEFAULT 'uppercase_numbers',
            avoid_ambiguous TINYINT NOT NULL DEFAULT 1,
            quantity INT NOT NULL,
            package_id INT NULL,
            created_by INT NULL,
            pushed_count INT NOT NULL DEFAULT 0,
            failed_count INT NOT NULL DEFAULT 0,
            created_at VARCHAR(19) NOT NULL,
            INDEX idx_batches_router_created (router_id, created_at),
            INDEX idx_batches_package_created (package_id, created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    batch_columns = mysql_table_columns(db, "voucher_batches")
    for name, definition in {
        "character_set": "VARCHAR(32) NOT NULL DEFAULT 'uppercase_numbers'",
        "avoid_ambiguous": "TINYINT NOT NULL DEFAULT 1",
    }.items():
        if name not in batch_columns:
            db.execute(f"ALTER TABLE voucher_batches ADD COLUMN `{name}` {definition}")
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS sales (
            id INT PRIMARY KEY AUTO_INCREMENT,
            voucher_id INT NOT NULL,
            cashier_id INT NULL,
            amount DECIMAL(10,2) NOT NULL DEFAULT 0.00,
            payment_method VARCHAR(64) NOT NULL DEFAULT 'Cash',
            timestamp VARCHAR(19) NOT NULL,
            INDEX idx_sales_timestamp (timestamp),
            INDEX idx_sales_cashier_timestamp (cashier_id, timestamp)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INT PRIMARY KEY AUTO_INCREMENT,
            actor_user_id INT NULL,
            router_id INT NULL,
            entity_type VARCHAR(64) NOT NULL,
            entity_id INT NULL,
            action VARCHAR(64) NOT NULL,
            message TEXT,
            created_at VARCHAR(19) NOT NULL,
            INDEX idx_audit_router_created (router_id, created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )


def migrate_wireguard_schema(db: sqlite3.Connection) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS wireguard_interfaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            interface_name TEXT NOT NULL,
            private_key TEXT NOT NULL,
            public_key TEXT NOT NULL,
            listen_port INTEGER NOT NULL DEFAULT 51820,
            address TEXT NOT NULL,
            mtu INTEGER NOT NULL DEFAULT 1420,
            notes TEXT,
            router_id INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (router_id) REFERENCES routers(id) ON DELETE SET NULL
        )
        """
    )
    columns = table_columns(db, "wireguard_interfaces")
    new_columns = {
        "private_key": "TEXT NOT NULL DEFAULT ''",
        "public_key": "TEXT NOT NULL DEFAULT ''",
        "listen_port": "INTEGER NOT NULL DEFAULT 51820",
        "address": "TEXT NOT NULL DEFAULT ''",
        "mtu": "INTEGER NOT NULL DEFAULT 1420",
        "notes": "TEXT",
        "router_id": "INTEGER",
        "created_at": "TEXT NOT NULL DEFAULT ''",
    }
    for name, definition in new_columns.items():
        if name not in columns:
            db.execute(f"ALTER TABLE wireguard_interfaces ADD COLUMN `{name}` {definition}")
    db.execute(
        """
        UPDATE wireguard_interfaces
        SET created_at = ?
        WHERE created_at IS NULL OR created_at = ''
        """,
        (timestamp(),),
    )


def migrate_mysql_wireguard_schema(db) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS wireguard_interfaces (
            id INT PRIMARY KEY AUTO_INCREMENT,
            interface_name VARCHAR(100) NOT NULL,
            private_key TEXT NOT NULL,
            public_key TEXT NOT NULL,
            listen_port INT NOT NULL DEFAULT 51820,
            address VARCHAR(100) NOT NULL,
            mtu INT NOT NULL DEFAULT 1420,
            notes TEXT NULL,
            router_id INT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_wireguard_interface_name (interface_name),
            INDEX idx_wireguard_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    columns = mysql_table_columns(db, "wireguard_interfaces")
    new_columns = {
        "private_key": "TEXT NOT NULL",
        "public_key": "TEXT NOT NULL",
        "listen_port": "INT NOT NULL DEFAULT 51820",
        "address": "VARCHAR(100) NOT NULL",
        "mtu": "INT NOT NULL DEFAULT 1420",
        "notes": "TEXT NULL",
        "router_id": "INT NULL",
        "created_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
    }
    for name, definition in new_columns.items():
        if name not in columns:
            db.execute(f"ALTER TABLE wireguard_interfaces ADD COLUMN `{name}` {definition}")


def migrate_wireguard_secrets(db) -> None:
    rows = db.execute("SELECT id, private_key FROM wireguard_interfaces").fetchall()
    for row in rows:
        private_key = row_value(row, "private_key")
        encrypted = encrypt_secret(private_key)
        if encrypted != private_key:
            db.execute("UPDATE wireguard_interfaces SET private_key = ? WHERE id = ?", (encrypted, row["id"]))


def migrate_legacy_secret_storage(db) -> None:
    for table, id_column, secret_column in [
        ("routers", "id", "router_password"),
        ("router_sessions", "token", "router_password"),
    ]:
        rows = db.execute(
            f"SELECT {id_column}, {secret_column} FROM {table}"
        ).fetchall()
        for row in rows:
            secret = row_value(row, secret_column)
            encrypted = encrypt_secret(secret)
            if encrypted != secret:
                db.execute(
                    f"UPDATE {table} SET {secret_column} = ? WHERE {id_column} = ?",
                    (encrypted, row[id_column]),
                )

    legacy = db.execute(
        "SELECT value FROM settings WHERE `key` = 'router_password'"
    ).fetchone()
    if legacy:
        secret = row_value(legacy, "value")
        encrypted = encrypt_secret(secret)
        if encrypted != secret:
            db.execute(
                "UPDATE settings SET value = ? WHERE `key` = 'router_password'",
                (encrypted,),
            )


def mysql_table_columns(db, table: str) -> list[str]:
    rows = db.execute(
        """
        SELECT COLUMN_NAME
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?
        """,
        (table,),
    ).fetchall()
    return [row["COLUMN_NAME"] for row in rows]


def table_columns(db: sqlite3.Connection, table: str) -> list[str]:
    return [row["name"] for row in db.execute(f"PRAGMA table_info({table})").fetchall()]


def migrate_login_attempt_schema(db: sqlite3.Connection) -> None:
    if "scope" not in table_columns(db, "router_login_attempts"):
        db.execute("ALTER TABLE router_login_attempts ADD COLUMN scope TEXT NOT NULL DEFAULT 'router'")


def first_router_id(db: sqlite3.Connection) -> int | None:
    row = db.execute("SELECT id FROM routers ORDER BY id LIMIT 1").fetchone()
    return int(row["id"]) if row else None


def migrate_legacy_router(db: sqlite3.Connection) -> None:
    router_count = int(db.execute("SELECT COUNT(*) FROM routers").fetchone()[0])
    if router_count:
        return

    settings = {
        row["key"]: row["value"]
        for row in db.execute("SELECT `key`, value FROM settings").fetchall()
    }
    voucher_count = int(db.execute("SELECT COUNT(*) FROM vouchers").fetchone()[0])

    if not any(settings.get(key) for key in ["router_ip", "router_username", "router_password"]) and not voucher_count:
        return

    now = timestamp()
    db.execute(
        """
        INSERT INTO routers (name, router_ip, api_port, router_username, router_password, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "Router 1",
            settings.get("router_ip", ""),
            settings.get("api_port", "8728") or "8728",
            settings.get("router_username", ""),
            encrypt_secret(settings.get("router_password", "")),
            now,
            now,
        ),
    )


def migrate_vouchers_schema(db: sqlite3.Connection) -> None:
    columns = table_columns(db, "vouchers")
    create_sql = db.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'vouchers'"
    ).fetchone()["sql"]

    if "router_id" in columns and "UNIQUE" not in create_sql.upper():
        return

    default_router_id = first_router_id(db)
    router_expr = "router_id" if "router_id" in columns else ("NULL" if default_router_id is None else str(default_router_id))

    db.execute(
        """
        CREATE TABLE vouchers_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            router_id INTEGER,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            profile TEXT NOT NULL,
            time_limit TEXT NOT NULL,
            routeros_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (router_id) REFERENCES routers(id) ON DELETE CASCADE
        )
        """
    )
    db.execute(
        f"""
        INSERT INTO vouchers_new (id, router_id, username, password, profile, time_limit, routeros_id, created_at, updated_at)
        SELECT id, {router_expr}, username, password, profile, time_limit, routeros_id, created_at, updated_at
        FROM vouchers
        """
    )
    db.execute("DROP TABLE vouchers")
    db.execute("ALTER TABLE vouchers_new RENAME TO vouchers")


def get_settings() -> dict[str, str]:
    defaults = {
        "router_ip": "",
        "api_port": "8728",
        "router_username": "",
        "router_password": "",
    }
    with closing(get_db()) as db:
        rows = db.execute("SELECT `key`, value FROM settings").fetchall()
    for row in rows:
        if row["key"] in defaults:
            defaults[row["key"]] = row["value"]
    defaults["router_password"] = decrypt_secret(defaults["router_password"])
    return defaults


def row_value(row, key: str, default: str = "") -> str:
    if row is None:
        return default
    if isinstance(row, dict):
        return str(row.get(key, default) or default)
    if key in row.keys():
        return str(row[key] or default)
    return default


def voucher_to_dict(voucher) -> dict[str, str]:
    fields = [
        "username",
        "password",
        "profile",
        "time_limit",
        "price",
        "data_limit",
        "shared_users",
        "status",
        "comment",
        "expiry_date",
        "expires_at",
        "package_id",
        "batch_id",
        "created_by",
        "routeros_id",
    ]
    return {field: row_value(voucher, field) for field in fields}


def router_to_settings(router) -> dict[str, str]:
    return {
        "router_ip": row_value(router, "router_ip"),
        "api_port": row_value(router, "api_port", "8728"),
        "router_username": row_value(router, "router_username"),
        "router_password": decrypt_secret(row_value(router, "router_password")),
    }


def router_to_form_data(router) -> dict[str, str]:
    return {
        "name": row_value(router, "name", "Router"),
        **router_to_settings(router),
    }


def router_to_safe_form_data(router) -> dict[str, str]:
    return {
        "name": row_value(router, "name", "Router"),
        "router_ip": row_value(router, "router_ip"),
        "api_port": row_value(router, "api_port", "8728"),
        "router_username": row_value(router, "router_username"),
        "router_password": "",
    }


def active_router_settings(router) -> dict[str, str]:
    login = get_router_session()
    if login and int(row_value(login, "router_id", "0")) == int(row_value(router, "id", "0")):
        return router_to_settings(login)
    return router_to_settings(router)


def hotspot_profile_names(router) -> list[str]:
    try:
        profiles = RouterClient(active_router_settings(router)).list_hotspot_profiles()
    except Exception as exc:
        flash(f"Could not load hotspot profiles from MikroTik router: {exc}", "warning")
        return []

    names = [str(profile.get("name", "")).strip() for profile in profiles]
    return [name for name in names if name]


def router_from_form(fallback) -> dict[str, str]:
    default_name = row_value(fallback, "name", "Router")
    fallback_password = decrypt_secret(row_value(fallback, "router_password"))
    submitted_password = request.form.get("router_password", "")
    return {
        "name": request.form.get("name", default_name).strip() or default_name,
        "router_ip": request.form.get("router_ip", row_value(fallback, "router_ip")).strip(),
        "api_port": request.form.get("api_port", row_value(fallback, "api_port", "8728")).strip() or "8728",
        "router_username": request.form.get("router_username", row_value(fallback, "router_username")).strip(),
        "router_password": submitted_password if submitted_password else fallback_password,
    }


def list_routers() -> list[sqlite3.Row]:
    with closing(get_db()) as db:
        return db.execute("SELECT * FROM routers ORDER BY name, id").fetchall()


def router_count_for_user(user_id: int) -> int:
    with closing(get_db()) as db:
        return int(db.execute("SELECT COUNT(*) FROM routers").fetchone()[0])


def get_router(router_id: int) -> sqlite3.Row | None:
    with closing(get_db()) as db:
        return db.execute("SELECT * FROM routers WHERE id = ?", (router_id,)).fetchone()


def find_router_by_login(router: dict[str, str]) -> sqlite3.Row | None:
    with closing(get_db()) as db:
        return db.execute(
            """
            SELECT * FROM routers
            WHERE router_ip = ? AND api_port = ? AND router_username = ?
            ORDER BY id LIMIT 1
            """,
            (router["router_ip"], router["api_port"], router["router_username"]),
        ).fetchone()


def first_router() -> sqlite3.Row | None:
    with closing(get_db()) as db:
        return db.execute("SELECT * FROM routers ORDER BY id LIMIT 1").fetchone()


def get_active_router() -> sqlite3.Row | None:
    def load_active_router():
        router_session = get_router_session()
        if router_session:
            router = get_router(int(router_session["router_id"]))
            if router:
                session["router_id"] = int(router["id"])
                return router
            clear_router_session()

        return None

    return request_cached("active_router", load_active_router)


def get_authorized_router(router_id: int) -> sqlite3.Row | None:
    active_router = get_active_router()
    if active_router and int(active_router["id"]) == int(router_id):
        return active_router
    return None


def set_active_router(router_id: int) -> None:
    session["router_id"] = int(router_id)


def require_active_router() -> sqlite3.Row | None:
    router = get_active_router()
    if not router:
        flash("Add or login to a router first.", "warning")
    return router


def insert_router(router: dict[str, str]) -> int:
    now = timestamp()
    with closing(get_db()) as db:
        cursor = db.execute(
            """
            INSERT INTO routers (name, router_ip, api_port, router_username, router_password, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                router["name"],
                router["router_ip"],
                router["api_port"],
                router["router_username"],
                encrypt_secret(router["router_password"]),
                now,
                now,
            ),
        )
        db.commit()
        return int(cursor.lastrowid)


def update_router(router_id: int, router: dict[str, str]) -> None:
    with closing(get_db()) as db:
        db.execute(
            """
            UPDATE routers
            SET name = ?, router_ip = ?, api_port = ?, router_username = ?, router_password = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                router["name"],
                router["router_ip"],
                router["api_port"],
                router["router_username"],
                encrypt_secret(router["router_password"]),
                timestamp(),
                router_id,
            ),
        )
        db.commit()


def delete_router(router_id: int) -> None:
    with closing(get_db()) as db:
        router = db.execute("SELECT id FROM routers WHERE id = ?", (router_id,)).fetchone()
        if not router:
            return
        history = db.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM vouchers WHERE router_id = ?) AS vouchers,
                (SELECT COUNT(*) FROM voucher_batches WHERE router_id = ?) AS batches,
                (SELECT COUNT(*) FROM packages WHERE router_id = ?) AS packages
            """,
            (router_id, router_id, router_id),
        ).fetchone()
        if any(parse_int(row_value(history, key, "0")) for key in ("vouchers", "batches", "packages")):
            raise ValueError("This router has package or voucher history and cannot be deleted.")
        db.execute("DELETE FROM routers WHERE id = ?", (router_id,))
        db.commit()


def default_wireguard_interface() -> dict[str, str]:
    return {
        "interface_name": "wg0",
        "private_key": "",
        "public_key": "",
        "listen_port": "51820",
        "address": "10.10.10.1/24",
        "mtu": "1420",
        "notes": "",
        "router_id": "",
    }


def wireguard_interface_from_form() -> dict[str, str]:
    return {
        "interface_name": request.form.get("interface_name", "").strip(),
        "private_key": request.form.get("private_key", "").strip(),
        "public_key": request.form.get("public_key", "").strip(),
        "listen_port": request.form.get("listen_port", "51820").strip() or "51820",
        "address": request.form.get("address", "").strip(),
        "mtu": request.form.get("mtu", "1420").strip() or "1420",
        "notes": request.form.get("notes", "").strip(),
        "router_id": request.form.get("router_id", "").strip(),
    }


def validate_wireguard_interface(interface: dict[str, str]) -> str | None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", interface["interface_name"]):
        return "Use a WireGuard interface name like wg0, wg-home, or wg_1."
    if not interface["private_key"]:
        return "Enter the server private key."
    if not interface["public_key"]:
        return "Enter the server public key."
    listen_port = parse_positive_int(interface["listen_port"], 0)
    if listen_port < 1 or listen_port > 65535:
        return "Listen port must be between 1 and 65535."
    mtu = parse_positive_int(interface["mtu"], 0)
    if mtu < 576 or mtu > 9000:
        return "MTU must be between 576 and 9000."
    try:
        ipaddress.ip_interface(interface["address"])
    except ValueError:
        return "Enter a valid WireGuard server address, for example 10.10.10.1/24."
    if interface.get("router_id"):
        if not get_router(parse_positive_int(interface["router_id"], 0)):
            return "Choose a saved router or leave router blank."
    return None


def list_wireguard_interfaces(router_id: int) -> list[sqlite3.Row]:
    with closing(get_db()) as db:
        return db.execute(
            """
            SELECT w.*, r.name AS router_name
            FROM wireguard_interfaces w
            LEFT JOIN routers r ON r.id = w.router_id
            WHERE w.router_id = ?
            ORDER BY w.created_at DESC, w.id DESC
            """,
            (router_id,),
        ).fetchall()


def get_wireguard_interface(interface_id: int, router_id: int) -> sqlite3.Row | None:
    with closing(get_db()) as db:
        return db.execute(
            """
            SELECT w.*, r.name AS router_name
            FROM wireguard_interfaces w
            LEFT JOIN routers r ON r.id = w.router_id
            WHERE w.id = ? AND w.router_id = ?
            """,
            (interface_id, router_id),
        ).fetchone()


def insert_wireguard_interface(interface: dict[str, str]) -> int:
    user_id = current_user_id()
    if not user_id:
        raise RuntimeError("Login with a router IP before saving WireGuard interfaces.")
    active_router = get_active_router()
    router_id = int(active_router["id"]) if active_router else None
    if not router_id:
        raise RuntimeError("An active router session is required for WireGuard settings.")
    now = timestamp()
    with closing(get_db()) as db:
        cursor = db.execute(
            """
            INSERT INTO wireguard_interfaces (
                interface_name, private_key, public_key, listen_port,
                address, mtu, notes, router_id, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                interface["interface_name"],
                encrypt_secret(interface["private_key"]),
                interface["public_key"],
                parse_positive_int(interface["listen_port"], 51820),
                interface["address"],
                parse_positive_int(interface["mtu"], 1420),
                interface.get("notes", ""),
                router_id,
                now,
            ),
        )
        db.commit()
        return int(cursor.lastrowid)


def build_wireguard_interface_script(interface) -> str:
    name = row_value(interface, "interface_name", "wg0")
    private_key = decrypt_secret(row_value(interface, "private_key"))
    public_key = row_value(interface, "public_key")
    listen_port = parse_positive_int(row_value(interface, "listen_port", "51820"), 51820)
    mtu = parse_positive_int(row_value(interface, "mtu", "1420"), 1420)
    address = row_value(interface, "address", "10.10.10.1/24")
    try:
        network = str(ipaddress.ip_interface(address).network)
    except ValueError:
        network = "10.10.10.0/24"

    return f"""#!/usr/bin/env bash
set -euo pipefail

WG_INTERFACE="{name}"
WG_ADDRESS="{address}"
WG_NETWORK="{network}"
WG_LISTEN_PORT="{listen_port}"
WG_MTU="{mtu}"
WAN_INTERFACE="${{WAN_INTERFACE:-eth0}}"

sudo apt update
sudo apt install wireguard ufw -y

sudo mkdir -p /etc/wireguard

sudo tee "/etc/wireguard/${{WG_INTERFACE}}.conf" > /dev/null << EOF
[Interface]
Address = {address}
ListenPort = {listen_port}
PrivateKey = {private_key}
MTU = {mtu}

# Server public key: {public_key}
PostUp = ufw route allow in on {name} out on $WAN_INTERFACE
PostUp = iptables -t nat -A POSTROUTING -s {network} -o $WAN_INTERFACE -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s {network} -o $WAN_INTERFACE -j MASQUERADE
EOF

sudo chmod 600 "/etc/wireguard/${{WG_INTERFACE}}.conf"

if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
fi
sudo sysctl -p

sudo ufw allow "${{WG_LISTEN_PORT}}/udp"
sudo systemctl enable "wg-quick@${{WG_INTERFACE}}"
sudo systemctl restart "wg-quick@${{WG_INTERFACE}}"
sudo systemctl status "wg-quick@${{WG_INTERFACE}}" --no-pager
"""


def dashboard_summary() -> dict[str, object]:
    user_id = current_user_id()
    if not user_id:
        return {}
    active_router = get_active_router()
    router_id = int(active_router["id"]) if active_router else None
    with closing(get_db()) as db:
        routers_total = int(db.execute("SELECT COUNT(*) FROM routers").fetchone()[0])
        vouchers_unused = vouchers_active = vouchers_expired = 0
        today_sales = Decimal("0.00")
        low_stock = []
        if router_id:
            counts = voucher_status_counts(router_id)
            vouchers_unused = counts.get("unused", 0)
            vouchers_active = counts.get("active", 0) + counts.get("online", 0) + counts.get("activated", 0)
            vouchers_expired = counts.get("expired", 0)
            today_sales = today_sales_total(router_id)
            low_stock = low_stock_packages(router_id)
    month_sales = period_sales_total(router_id, datetime.now().strftime("%Y-%m-01")) if router_id else Decimal("0.00")
    today_target = max(Decimal("1.00"), month_sales / Decimal("30")) if router_id else Decimal("1.00")
    return {
        "routers_total": routers_total,
        "vouchers_unused": vouchers_unused,
        "vouchers_active": vouchers_active,
        "vouchers_expired": vouchers_expired,
        "today_sales": format_money(today_sales),
        "month_sales": format_money(month_sales),
        "today_target": format_money(today_target),
        "today_target_percent": min(100, int((today_sales / today_target) * Decimal("100"))) if today_target else 0,
        "low_stock": low_stock,
        "charts": dashboard_charts(router_id) if router_id else empty_dashboard_charts(),
    }


def empty_dashboard_charts() -> dict[str, object]:
    labels = dashboard_date_labels(14)
    return {
        "sales_trend": {"labels": labels, "revenue": [0 for _ in labels], "sales": [0 for _ in labels], "peak": None},
        "cumulative_revenue": {"labels": labels, "revenue": [0 for _ in labels]},
        "voucher_activity": {"labels": labels, "created": [0 for _ in labels], "sold": [0 for _ in labels]},
        "voucher_status": {"labels": ["Unused", "Active", "Expired", "Removed", "Disabled"], "values": [0, 0, 0, 0, 0]},
        "package_mix": {"labels": [], "values": [], "mode": "empty"},
    }


def dashboard_charts(router_id: int) -> dict[str, object]:
    sales_trend = dashboard_sales_trend(router_id)
    return {
        "sales_trend": sales_trend,
        "cumulative_revenue": dashboard_cumulative_revenue(sales_trend),
        "voucher_activity": dashboard_voucher_activity(router_id),
        "voucher_status": dashboard_voucher_status(router_id),
        "package_mix": dashboard_package_mix(router_id),
    }


def dashboard_date_labels(days: int) -> list[str]:
    today = datetime.now().date()
    return [(today - timedelta(days=offset)).strftime("%Y-%m-%d") for offset in range(days - 1, -1, -1)]


def dashboard_sales_trend(router_id: int, days: int = 14) -> dict[str, object]:
    labels = dashboard_date_labels(days)
    revenue_by_day = {label: Decimal("0.00") for label in labels}
    sales_by_day = {label: 0 for label in labels}
    with closing(get_db()) as db:
        rows = db.execute(
            """
            SELECT SUBSTR(s.timestamp, 1, 10) AS sale_day,
                   COALESCE(SUM(s.amount), 0) AS total,
                   COUNT(*) AS sale_count
            FROM sales s
            JOIN vouchers v ON v.id = s.voucher_id
            WHERE v.router_id = ? AND s.timestamp >= ?
            GROUP BY SUBSTR(s.timestamp, 1, 10)
            ORDER BY sale_day
            """,
            (router_id, labels[0]),
        ).fetchall()

    for row in rows:
        day = row_value(row, "sale_day")
        if day in revenue_by_day:
            revenue_by_day[day] = parse_price(row_value(row, "total")) or Decimal("0.00")
            sales_by_day[day] = parse_positive_int(row_value(row, "sale_count"), 0)

    revenue = [float(revenue_by_day[label]) for label in labels]
    sales = [sales_by_day[label] for label in labels]
    peak = None
    if revenue and max(revenue) > 0:
        peak_index = revenue.index(max(revenue))
        peak = {"index": peak_index, "label": labels[peak_index], "value": revenue[peak_index]}
    return {"labels": labels, "revenue": revenue, "sales": sales, "peak": peak}


def dashboard_cumulative_revenue(sales_trend: dict[str, object]) -> dict[str, object]:
    running = Decimal("0.00")
    values = []
    for value in sales_trend.get("revenue", []):
        running += parse_price(value) or Decimal("0.00")
        values.append(float(running))
    return {"labels": sales_trend.get("labels", []), "revenue": values}


def dashboard_voucher_activity(router_id: int, days: int = 14) -> dict[str, object]:
    labels = dashboard_date_labels(days)
    created_by_day = {label: 0 for label in labels}
    sold_by_day = {label: 0 for label in labels}
    with closing(get_db()) as db:
        created_rows = db.execute(
            """
            SELECT SUBSTR(created_at, 1, 10) AS item_day, COUNT(*) AS total
            FROM vouchers
            WHERE router_id = ? AND created_at >= ?
            GROUP BY SUBSTR(created_at, 1, 10)
            ORDER BY item_day
            """,
            (router_id, labels[0]),
        ).fetchall()
        sold_rows = db.execute(
            """
            SELECT SUBSTR(s.timestamp, 1, 10) AS item_day, COUNT(*) AS total
            FROM sales s
            JOIN vouchers v ON v.id = s.voucher_id
            WHERE v.router_id = ? AND s.timestamp >= ?
            GROUP BY SUBSTR(s.timestamp, 1, 10)
            ORDER BY item_day
            """,
            (router_id, labels[0]),
        ).fetchall()

    for row in created_rows:
        day = row_value(row, "item_day")
        if day in created_by_day:
            created_by_day[day] = parse_positive_int(row_value(row, "total"), 0)
    for row in sold_rows:
        day = row_value(row, "item_day")
        if day in sold_by_day:
            sold_by_day[day] = parse_positive_int(row_value(row, "total"), 0)

    return {
        "labels": labels,
        "created": [created_by_day[label] for label in labels],
        "sold": [sold_by_day[label] for label in labels],
    }


def dashboard_voucher_status(router_id: int) -> dict[str, object]:
    counts = voucher_status_counts(router_id)
    active = counts.get("active", 0) + counts.get("online", 0) + counts.get("activated", 0) + counts.get("used", 0)
    removed = counts.get("removed", 0) + counts.get("deleted", 0)
    return {
        "labels": ["Unused", "Active", "Expired", "Removed", "Disabled"],
        "values": [
            counts.get("unused", 0),
            active,
            counts.get("expired", 0),
            removed,
            counts.get("disabled", 0),
        ],
    }


def dashboard_package_mix(router_id: int) -> dict[str, object]:
    with closing(get_db()) as db:
        rows = db.execute(
            """
            SELECT COALESCE(NULLIF(v.profile, ''), 'No profile') AS package_name,
                   COALESCE(SUM(s.amount), 0) AS total
            FROM sales s
            JOIN vouchers v ON v.id = s.voucher_id
            WHERE v.router_id = ?
            GROUP BY COALESCE(NULLIF(v.profile, ''), 'No profile')
            ORDER BY total DESC
            LIMIT 5
            """,
            (router_id,),
        ).fetchall()
    labels = [row_value(row, "package_name", "No profile") for row in rows]
    values = [float(parse_price(row_value(row, "total")) or Decimal("0.00")) for row in rows]
    return {"labels": labels, "values": values, "mode": "donut" if 0 < len(labels) <= 5 else "empty"}


def default_package() -> dict[str, str]:
    return {
        "name": "",
        "rate_limit": "5M/2M",
        "validity_period": "1d",
        "data_cap": "",
        "price": "0.00",
        "archived": "0",
    }


def package_from_form(fallback=None) -> dict[str, str]:
    fallback = fallback or {}
    return {
        "name": request.form.get("name", row_value(fallback, "name")).strip(),
        "rate_limit": request.form.get("rate_limit", row_value(fallback, "rate_limit", "5M/2M")).strip(),
        "validity_period": request.form.get("validity_period", row_value(fallback, "validity_period", "1d")).strip() or "1d",
        "data_cap": request.form.get("data_cap", row_value(fallback, "data_cap")).strip(),
        "price": request.form.get("price", row_value(fallback, "price", "0.00")).strip() or "0.00",
        "archived": request.form.get("archived", row_value(fallback, "archived", "0")).strip() or "0",
    }


def package_to_form(package) -> dict[str, str]:
    return {
        "id": row_value(package, "id"),
        "name": row_value(package, "name"),
        "rate_limit": row_value(package, "rate_limit"),
        "validity_period": row_value(package, "validity_period"),
        "data_cap": row_value(package, "data_cap"),
        "price": format_money(row_value(package, "price", "0.00")),
        "archived": row_value(package, "archived", "0"),
    }


def validate_package(package: dict[str, str]) -> str | None:
    if not package["name"]:
        return "Enter a package name."
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", package["name"]):
        return "Use a short package name without spaces, for example Day-5M or Weekly_10M."
    validity_text = package["validity_period"].strip().lower()
    if parse_duration_seconds(validity_text, zero_as_unlimited=True) is None and validity_text not in {"0s", "0", "lifetime", "unlimited"}:
        return "Enter a validity like 1h, 1d, 1w, 30d, or 0s for lifetime."
    if package["data_cap"] and parse_int(package["data_cap"]) is None:
        return "Use a data cap like 500M, 2G, or leave it blank."
    if parse_price(package["price"]) is None:
        return "Package price must be a number and cannot be negative."
    return None


def list_packages(router_id: int, include_archived: bool = False) -> list[sqlite3.Row]:
    archived_filter = "" if include_archived else "AND p.archived = 0"
    with closing(get_db()) as db:
        return db.execute(
            f"""
            SELECT
                p.*,
                SUM(CASE WHEN v.status = 'unused' THEN 1 ELSE 0 END) AS unused_vouchers,
                SUM(CASE WHEN v.status = 'active' THEN 1 ELSE 0 END) AS active_vouchers,
                SUM(CASE WHEN v.status IN ('used', 'expired', 'removed', 'deleted') THEN 1 ELSE 0 END) AS retired_vouchers,
                COUNT(v.id) AS total_vouchers
            FROM packages p
            LEFT JOIN vouchers v ON v.package_id = p.id AND v.router_id = p.router_id
            WHERE p.router_id = ? {archived_filter}
            GROUP BY
                p.id, p.router_id, p.name, p.rate_limit, p.validity_period,
                p.data_cap, p.price, p.archived, p.created_at, p.updated_at
            ORDER BY p.archived, p.name
            """,
            (router_id,),
        ).fetchall()


def get_package(package_id: int, router_id: int) -> sqlite3.Row | None:
    with closing(get_db()) as db:
        return db.execute(
            "SELECT * FROM packages WHERE id = ? AND router_id = ?",
            (package_id, router_id),
        ).fetchone()


def insert_package(package: dict[str, str], router_id: int) -> int:
    now = timestamp()
    with closing(get_db()) as db:
        cursor = db.execute(
            """
            INSERT INTO packages (router_id, name, rate_limit, validity_period, data_cap, price, archived, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                router_id,
                package["name"],
                package["rate_limit"],
                package["validity_period"],
                package["data_cap"],
                format_money(package["price"]),
                parse_positive_int(package.get("archived"), 0),
                now,
                now,
            ),
        )
        db.commit()
        return int(cursor.lastrowid)


def update_package(package_id: int, package: dict[str, str], router_id: int) -> None:
    with closing(get_db()) as db:
        db.execute(
            """
            UPDATE packages
            SET name = ?, rate_limit = ?, validity_period = ?, data_cap = ?, price = ?, archived = ?, updated_at = ?
            WHERE id = ? AND router_id = ?
            """,
            (
                package["name"],
                package["rate_limit"],
                package["validity_period"],
                package["data_cap"],
                format_money(package["price"]),
                parse_positive_int(package.get("archived"), 0),
                timestamp(),
                package_id,
                router_id,
            ),
        )
        db.commit()


def set_package_archived(package_id: int, router_id: int, archived: bool) -> None:
    with closing(get_db()) as db:
        db.execute(
            "UPDATE packages SET archived = ?, updated_at = ? WHERE id = ? AND router_id = ?",
            (1 if archived else 0, timestamp(), package_id, router_id),
        )
        db.commit()


def package_to_hotspot_profile(package) -> dict[str, str]:
    return {
        "name": row_value(package, "name"),
        "rate_limit": row_value(package, "rate_limit"),
        "shared_users": "1",
        "session_timeout": "",
        "idle_timeout": "",
    }


def default_voucher_batch() -> dict[str, str]:
    return {
        "package_id": "",
        "quantity": "10",
        "prefix": "KT",
        "code_length": "8",
        "password_length": "6",
        "character_set": "uppercase_numbers",
        "avoid_ambiguous": "1",
        "payment_method": "Cash",
    }


def voucher_batch_from_form() -> dict[str, str]:
    return {
        "package_id": request.form.get("package_id", "").strip(),
        "quantity": request.form.get("quantity", "10").strip() or "10",
        "prefix": request.form.get("prefix", "KT").strip().upper(),
        "code_length": request.form.get("code_length", "8").strip() or "8",
        "password_length": request.form.get("password_length", "6").strip() or "6",
        "character_set": request.form.get("character_set", "uppercase_numbers").strip() or "uppercase_numbers",
        "avoid_ambiguous": "1" if request.form.get("avoid_ambiguous") == "1" else "0",
        "payment_method": request.form.get("payment_method", "Cash").strip() or "Cash",
    }


def validate_voucher_batch(form: dict[str, str], packages: list[sqlite3.Row]) -> str | None:
    package_ids = {int(row["id"]) for row in packages}
    if parse_positive_int(form["package_id"], 0) not in package_ids:
        return "Choose a package."
    quantity = parse_positive_int(form["quantity"], 0)
    if quantity < 1 or quantity > 2000:
        return "Generate between 1 and 2,000 vouchers at a time."
    prefix = form["prefix"]
    if prefix and not re.fullmatch(r"[A-Z0-9-]{1,12}", prefix):
        return "Use a short uppercase prefix with letters, numbers, or hyphen."
    code_length = parse_positive_int(form["code_length"], 0)
    password_length = parse_positive_int(form["password_length"], 0)
    if code_length < 6 or code_length > 18:
        return "Code length must be between 6 and 18."
    if password_length < 4 or password_length > 18:
        return "Password length must be between 4 and 18."
    if form["character_set"] not in {"uppercase_numbers", "uppercase", "numbers"}:
        return "Choose a valid voucher character set."
    if len(voucher_code_alphabet(form["character_set"], form["avoid_ambiguous"] == "1")) < 8:
        return "The selected voucher character set is too small."
    if prefix and len(prefix) >= code_length:
        return "Code length must be longer than the prefix."
    return None


def create_voucher_batch(router, package, form: dict[str, str]) -> tuple[list[int], int]:
    router_id = int(router["id"])
    quantity = parse_positive_int(form["quantity"], 10)
    prefix = form["prefix"].upper()
    character_set = form["character_set"]
    avoid_ambiguous = form["avoid_ambiguous"] == "1"
    alphabet = voucher_code_alphabet(character_set, avoid_ambiguous)
    user_id = current_user_id()
    now = timestamp()
    with closing(get_db()) as db:
        cursor = db.execute(
            """
            INSERT INTO voucher_batches (
                router_id, prefix, character_set, avoid_ambiguous,
                quantity, package_id, created_by, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                router_id,
                prefix,
                character_set,
                1 if avoid_ambiguous else 0,
                quantity,
                int(package["id"]),
                user_id,
                now,
            ),
        )
        batch_id = int(cursor.lastrowid)
        generated_codes: set[str] = set()
        voucher_ids = []
        for _ in range(quantity):
            for attempt in range(25):
                code = generate_unique_voucher_code(
                    prefix,
                    parse_positive_int(form["code_length"], 8),
                    generated_codes,
                    alphabet,
                )
                generated_codes.add(code)
                voucher = voucher_from_package(code, random_code(parse_positive_int(form["password_length"], 6)), package, batch_id, user_id)
                try:
                    cursor = db.execute(
                        """
                        INSERT INTO vouchers (
                            router_id, package_id, batch_id, created_by, username, password, profile, time_limit,
                            price, data_limit, shared_users, status, `comment`, expiry_date, expires_at, removed_at,
                            routeros_id, created_at, updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            router_id,
                            int(package["id"]),
                            batch_id,
                            user_id,
                            voucher["username"],
                            voucher["password"],
                            voucher["profile"],
                            voucher["time_limit"],
                            voucher["price"],
                            voucher["data_limit"],
                            voucher["shared_users"],
                            voucher["status"],
                            voucher["comment"],
                            voucher["expiry_date"],
                            voucher["expires_at"],
                            voucher["removed_at"],
                            "",
                            now,
                            now,
                        ),
                    )
                except Exception as exc:
                    if is_database_integrity_error(exc) and attempt < 24:
                        continue
                    raise
                voucher_ids.append(int(cursor.lastrowid))
                break
        db.commit()
    return voucher_ids, batch_id


def generate_unique_voucher_code(prefix: str, length: int, existing_codes: set[str], alphabet: str | None = None) -> str:
    usable_length = max(1, length - len(prefix))
    for _ in range(1000):
        code = f"{prefix}{random_code(usable_length, alphabet)}"
        if code not in existing_codes:
            return code
    raise RuntimeError("Could not generate a unique voucher code. Use a longer code length.")


def voucher_from_package(code: str, password: str, package, batch_id: int | None = None, user_id: int | None = None) -> dict[str, str]:
    return {
        "username": code,
        "password": password,
        "profile": row_value(package, "name"),
        "time_limit": row_value(package, "validity_period", "1d"),
        "price": format_money(row_value(package, "price", "0.00")),
        "data_limit": str(parse_int(row_value(package, "data_cap")) or "") if row_value(package, "data_cap") else "",
        "shared_users": "1",
        "status": "unused",
        "comment": f"Batch {batch_id}" if batch_id else "",
        "expiry_date": "",
        "expires_at": "",
        "removed_at": "",
        "package_id": row_value(package, "id"),
        "batch_id": str(batch_id or ""),
        "created_by": str(user_id or ""),
    }


def push_vouchers_to_router_async(app: Flask, router, settings: dict[str, str], voucher_ids: list[int], batch_id: int) -> None:
    if is_production():
        LOGGER.info("voucher batch queued for scheduled sync batch=%s vouchers=%s router=%s", batch_id, len(voucher_ids), router["id"])
        return
    thread = threading.Thread(
        target=push_vouchers_to_router_worker,
        args=(app, int(router["id"]), settings, voucher_ids, batch_id, current_user_id()),
        daemon=True,
    )
    thread.start()


def push_vouchers_to_router_worker(app: Flask, router_id: int, settings: dict[str, str], voucher_ids: list[int], batch_id: int, actor_user_id: int | None) -> None:
    pushed = 0
    failed = 0
    LOGGER.info("voucher push started batch=%s vouchers=%s router=%s", batch_id, len(voucher_ids), router_id)
    with app.app_context():
        client = RouterClient(settings)
        try:
            for voucher_id in voucher_ids:
                try:
                    voucher = get_voucher(voucher_id, router_id)
                    if not voucher or row_value(voucher, "status", "unused") != "unused":
                        continue
                    if row_value(voucher, "routeros_id"):
                        pushed += 1
                        continue
                    routeros_id = client.create_voucher(voucher_to_dict(voucher))
                    update_voucher_sync_fields(voucher_id, router_id, {"routeros_id": routeros_id or ""})
                    pushed += 1
                except Exception as exc:
                    failed += 1
                    LOGGER.warning("voucher push failed batch=%s voucher=%s router=%s error=%s", batch_id, voucher_id, router_id, exc)
            update_voucher_batch_push_counts(batch_id, router_id, pushed, failed)
            audit_log(actor_user_id, router_id, "voucher_batch", batch_id, "push", f"Pushed {pushed}, failed {failed}")
        finally:
            client.close()
    LOGGER.info("voucher push finished batch=%s pushed=%s failed=%s router=%s", batch_id, pushed, failed, router_id)


def list_voucher_batches(router_id: int) -> list[sqlite3.Row]:
    with closing(get_db()) as db:
        return db.execute(
            """
            SELECT b.*, p.name AS package_name
            FROM voucher_batches b
            LEFT JOIN packages p ON p.id = b.package_id
            WHERE b.router_id = ?
            ORDER BY b.created_at DESC, b.id DESC
            """,
            (router_id,),
        ).fetchall()


def get_voucher_batch(batch_id: int, router_id: int) -> sqlite3.Row | None:
    with closing(get_db()) as db:
        return db.execute(
            "SELECT * FROM voucher_batches WHERE id = ? AND router_id = ?",
            (batch_id, router_id),
        ).fetchone()


def list_vouchers_by_batch(router_id: int, batch_id: int) -> list[sqlite3.Row]:
    with closing(get_db()) as db:
        return db.execute(
            "SELECT * FROM vouchers WHERE router_id = ? AND batch_id = ? ORDER BY id",
            (router_id, batch_id),
        ).fetchall()


def update_voucher_batch_push_counts(batch_id: int, router_id: int, pushed: int, failed: int) -> None:
    with closing(get_db()) as db:
        db.execute(
            "UPDATE voucher_batches SET pushed_count = ?, failed_count = ? WHERE id = ? AND router_id = ?",
            (pushed, failed, batch_id, router_id),
        )
        db.commit()


def record_sale(voucher_id: int, router_id: int, amount: str, payment_method: str = "Cash") -> None:
    user_id = current_user_id()
    with closing(get_db()) as db:
        voucher = db.execute("SELECT id FROM vouchers WHERE id = ? AND router_id = ?", (voucher_id, router_id)).fetchone()
        if not voucher:
            raise ValueError("Voucher not found.")
        existing = db.execute("SELECT id FROM sales WHERE voucher_id = ? LIMIT 1", (voucher_id,)).fetchone()
        if existing:
            raise ValueError("This voucher sale is already recorded.")
        try:
            db.execute(
                """
                INSERT INTO sales (voucher_id, cashier_id, amount, payment_method, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                (voucher_id, user_id, format_money(amount), payment_method or "Cash", timestamp()),
            )
        except Exception as exc:
            if is_database_integrity_error(exc):
                raise ValueError("This voucher sale is already recorded.") from exc
            raise
        db.commit()


def today_sales_total(router_id: int) -> Decimal:
    today = datetime.now().strftime("%Y-%m-%d")
    with closing(get_db()) as db:
        row = db.execute(
            """
            SELECT COALESCE(SUM(s.amount), 0) AS total
            FROM sales s
            JOIN vouchers v ON v.id = s.voucher_id
            WHERE v.router_id = ? AND s.timestamp >= ?
            """,
            (router_id, today),
        ).fetchone()
    return parse_price(row["total"] if row else "0") or Decimal("0.00")


def sales_summary(router_id: int) -> dict[str, str]:
    return {
        "today_total": format_money(today_sales_total(router_id)),
        "month_total": format_money(period_sales_total(router_id, datetime.now().strftime("%Y-%m-01"))),
    }


def period_sales_total(router_id: int, start_date: str) -> Decimal:
    with closing(get_db()) as db:
        row = db.execute(
            """
            SELECT COALESCE(SUM(s.amount), 0) AS total
            FROM sales s
            JOIN vouchers v ON v.id = s.voucher_id
            WHERE v.router_id = ? AND s.timestamp >= ?
            """,
            (router_id, start_date),
        ).fetchone()
    return parse_price(row["total"] if row else "0") or Decimal("0.00")


def list_sales(router_id: int, limit: int = 100) -> list[sqlite3.Row]:
    with closing(get_db()) as db:
        return db.execute(
            """
            SELECT s.*, v.username, v.profile
            FROM sales s
            JOIN vouchers v ON v.id = s.voucher_id
            WHERE v.router_id = ?
            ORDER BY s.timestamp DESC, s.id DESC
            LIMIT ?
            """,
            (router_id, limit),
        ).fetchall()


def low_stock_packages(router_id: int, threshold: int = 5) -> list[dict[str, object]]:
    with closing(get_db()) as db:
        rows = db.execute(
            """
            SELECT p.name, COUNT(v.id) AS unused
            FROM packages p
            LEFT JOIN vouchers v
                ON v.package_id = p.id
                AND v.router_id = p.router_id
                AND v.status = 'unused'
            WHERE p.router_id = ? AND p.archived = 0
            GROUP BY p.id, p.name
            HAVING COUNT(v.id) < ?
            ORDER BY p.name
            """,
            (router_id, threshold),
        ).fetchall()
    return [{"name": row["name"], "unused": int(row["unused"])} for row in rows]


def audit_log(actor_user_id: int | None, router_id: int | None, entity_type: str, entity_id: int | None, action: str, message: str = "") -> None:
    LOGGER.info(
        "audit actor=%s router=%s entity=%s:%s action=%s message=%s",
        actor_user_id,
        router_id,
        entity_type,
        entity_id,
        action,
        message,
    )
    try:
        with closing(get_db()) as db:
            db.execute(
                """
                INSERT INTO audit_logs (actor_user_id, router_id, entity_type, entity_id, action, message, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (actor_user_id, router_id, entity_type, entity_id, action, message, timestamp()),
            )
            db.commit()
    except Exception as exc:
        LOGGER.warning("audit log failed action=%s entity=%s:%s error=%s", action, entity_type, entity_id, exc)


VOUCHER_STATUSES = ["unused", "active", "expired", "removed", "disabled", "activated", "online", "used", "deleted"]
DISPLAY_VOUCHER_STATUSES = ["unused", "active", "used", "expired", "removed", "disabled"]
TERMINAL_VOUCHER_STATUSES = {"expired", "removed", "deleted"}
VOUCHER_PAGE_SIZES = (10, 25, 50, 100)
DEFAULT_VOUCHERS_PER_PAGE = 25
MAX_VOUCHERS_PER_PAGE = 250
DEFAULT_PRINT_VOUCHER_LIMIT = 200
MAX_PRINT_VOUCHER_LIMIT = 500
VOUCHER_SORT_COLUMNS = {
    "code": "username",
    "password": "password",
    "profile": "profile",
    "time": "time_limit",
    "price": "price",
    "data": "data_limit",
    "users": "shared_users",
    "online": "online_users",
    "status": "status",
    "activated": "activated_at",
    "time_used": "uptime_used",
    "data_used": "data_used",
    "expiry": "expiry_date",
    "created": "created_at",
}


def voucher_query_state() -> dict[str, object]:
    status = request.args.get("status", "all").strip().lower()
    if status not in ["all", *DISPLAY_VOUCHER_STATUSES]:
        status = "all"

    date_field = request.args.get("date_field", "created").strip().lower()
    if date_field not in {"created", "expiry"}:
        date_field = "created"

    sort = request.args.get("sort", "created").strip().lower()
    if sort not in VOUCHER_SORT_COLUMNS:
        sort = "created"

    direction = request.args.get("direction", "desc").strip().lower()
    if direction not in {"asc", "desc"}:
        direction = "desc"

    return {
        "q": request.args.get("q", "").strip()[:120],
        "status": status,
        "profile": request.args.get("profile", "").strip()[:191],
        "date_field": date_field,
        "date_from": valid_voucher_filter_date(request.args.get("date_from", "")),
        "date_to": valid_voucher_filter_date(request.args.get("date_to", "")),
        "sort": sort,
        "direction": direction,
        "per_page": voucher_page_size(),
    }


def valid_voucher_filter_date(value: str) -> str:
    candidate = (value or "").strip()
    if not candidate:
        return ""
    try:
        return datetime.strptime(candidate, "%Y-%m-%d").strftime("%Y-%m-%d")
    except ValueError:
        return ""


def voucher_query_params(state: dict[str, object], **updates) -> dict[str, object]:
    params = dict(state)
    params.update(updates)
    if not params.get("q"):
        params.pop("q", None)
    if params.get("status") == "all":
        params.pop("status", None)
    if not params.get("profile"):
        params.pop("profile", None)
    if not params.get("date_from"):
        params.pop("date_from", None)
    if not params.get("date_to"):
        params.pop("date_to", None)
    if not params.get("date_from") and not params.get("date_to"):
        params.pop("date_field", None)
    if not params.get("page") or int(params.get("page") or 1) <= 1:
        params.pop("page", None)
    return params


def voucher_page_url(state: dict[str, object], **updates) -> str:
    return url_for("vouchers", **voucher_query_params(state, **updates))


def voucher_active_filters(state: dict[str, object]) -> list[dict[str, str]]:
    filters: list[dict[str, str]] = []
    if state["q"]:
        filters.append({"label": f'Search: "{state["q"]}"', "url": voucher_page_url(state, q="", page=1)})
    if state["status"] != "all":
        filters.append({"label": f'Status: {str(state["status"]).title()}', "url": voucher_page_url(state, status="all", page=1)})
    if state["profile"]:
        filters.append({"label": f'Profile: {state["profile"]}', "url": voucher_page_url(state, profile="", page=1)})
    if state["date_from"] or state["date_to"]:
        date_label = "Created" if state["date_field"] == "created" else "Expiry"
        date_range = f'{state["date_from"] or "Any"} to {state["date_to"] or "Any"}'
        filters.append(
            {
                "label": f"{date_label}: {date_range}",
                "url": voucher_page_url(state, date_from="", date_to="", page=1),
            }
        )
    return filters


def voucher_filter_conditions(router_id: int, state: dict[str, object]) -> tuple[list[str], list[object]]:
    where = ["router_id = ?"]
    params: list[object] = [router_id]
    status = str(state["status"])
    if status == "active":
        where.append("status IN ('active', 'online', 'activated')")
    elif status == "removed":
        where.append("status IN ('removed', 'deleted')")
    elif status in VOUCHER_STATUSES:
        where.append("status = ?")
        params.append(status)

    search = str(state["q"]).lower()
    if search:
        pattern = f"%{search}%"
        columns = [
            "username",
            "password",
            "profile",
            "status",
            "`comment`",
            "first_login_mac",
            "first_login_ip",
            "device_name",
            "time_limit",
            "expiry_date",
        ]
        where.append("(" + " OR ".join(f"LOWER(COALESCE({column}, '')) LIKE ?" for column in columns) + ")")
        params.extend([pattern] * len(columns))

    if state["profile"]:
        where.append("profile = ?")
        params.append(state["profile"])

    date_column = "created_at" if state["date_field"] == "created" else "expiry_date"
    if state["date_from"]:
        where.append(f"{date_column} >= ?")
        params.append(state["date_from"])
    if state["date_to"]:
        end_date = datetime.strptime(str(state["date_to"]), "%Y-%m-%d") + timedelta(days=1)
        where.append(f"{date_column} < ?")
        params.append(end_date.strftime("%Y-%m-%d"))
    return where, params


def list_filtered_vouchers(
    router_id: int,
    state: dict[str, object],
    *,
    limit: int | None = None,
    offset: int = 0,
) -> list[sqlite3.Row]:
    where, params = voucher_filter_conditions(router_id, state)
    sort_column = VOUCHER_SORT_COLUMNS[str(state["sort"])]
    direction = "ASC" if state["direction"] == "asc" else "DESC"
    sql = f"SELECT * FROM vouchers WHERE {' AND '.join(where)} ORDER BY {sort_column} {direction}, id {direction}"
    if limit is not None:
        sql += " LIMIT ? OFFSET ?"
        params.extend([int(limit), max(0, int(offset))])
    with closing(get_db()) as db:
        return db.execute(sql, tuple(params)).fetchall()


def count_filtered_vouchers(router_id: int, state: dict[str, object]) -> int:
    where, params = voucher_filter_conditions(router_id, state)
    with closing(get_db()) as db:
        return int(db.execute(f"SELECT COUNT(*) FROM vouchers WHERE {' AND '.join(where)}", tuple(params)).fetchone()[0])


def list_voucher_profiles(router_id: int) -> list[str]:
    with closing(get_db()) as db:
        rows = db.execute(
            "SELECT DISTINCT profile FROM vouchers WHERE router_id = ? AND profile <> '' ORDER BY profile",
            (router_id,),
        ).fetchall()
    return [str(row["profile"]) for row in rows]


def list_vouchers(router_id: int, status: str = "all", *, limit: int | None = None, offset: int = 0) -> list[sqlite3.Row]:
    with closing(get_db()) as db:
        if status == "active":
            sql = "SELECT * FROM vouchers WHERE router_id = ? AND status IN ('active', 'online', 'activated') ORDER BY created_at DESC, id DESC"
            params: tuple = (router_id,)
        elif status == "removed":
            sql = "SELECT * FROM vouchers WHERE router_id = ? AND status IN ('removed', 'deleted') ORDER BY created_at DESC, id DESC"
            params = (router_id,)
        elif status in VOUCHER_STATUSES:
            sql = "SELECT * FROM vouchers WHERE router_id = ? AND status = ? ORDER BY created_at DESC, id DESC"
            params: tuple = (router_id, status)
        else:
            sql = "SELECT * FROM vouchers WHERE router_id = ? ORDER BY created_at DESC, id DESC"
            params = (router_id,)

        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            params = (*params, int(limit), max(0, int(offset)))

        return db.execute(sql, params).fetchall()


def get_voucher(voucher_id: int, router_id: int) -> sqlite3.Row | None:
    with closing(get_db()) as db:
        return db.execute(
            "SELECT * FROM vouchers WHERE id = ? AND router_id = ?",
            (voucher_id, router_id),
        ).fetchone()


def get_voucher_by_username(username: str, router_id: int) -> sqlite3.Row | None:
    with closing(get_db()) as db:
        return db.execute(
            "SELECT * FROM vouchers WHERE username = ? AND router_id = ?",
            (username, router_id),
        ).fetchone()


def count_vouchers(router_id: int | None = None, status: str = "all") -> int:
    with closing(get_db()) as db:
        if router_id is None:
            return int(db.execute("SELECT COUNT(*) FROM vouchers").fetchone()[0])
        if status in VOUCHER_STATUSES:
            return int(
                db.execute(
                    "SELECT COUNT(*) FROM vouchers WHERE router_id = ? AND status = ?",
                    (router_id, status),
                ).fetchone()[0]
            )
        return int(db.execute("SELECT COUNT(*) FROM vouchers WHERE router_id = ?", (router_id,)).fetchone()[0])


def voucher_status_counts(router_id: int) -> dict[str, int]:
    counts = {status: 0 for status in VOUCHER_STATUSES}
    with closing(get_db()) as db:
        rows = db.execute(
            "SELECT status, COUNT(*) AS total FROM vouchers WHERE router_id = ? GROUP BY status",
            (router_id,),
        ).fetchall()
    for row in rows:
        status = normalize_voucher_status(row["status"] or "unused")
        counts[status] = counts.get(status, 0) + int(row["total"])
    counts["all"] = sum(counts.values())
    return counts


def normalize_voucher_status(status: str) -> str:
    value = (status or "unused").strip().lower()
    if value in ["online", "activated"]:
        return "active"
    if value == "deleted":
        return "removed"
    return value if value in VOUCHER_STATUSES else "unused"


VOUCHER_EXPORT_COLUMNS = [
    "Voucher code",
    "Password",
    "Plan/package",
    "Duration",
    "Price",
    "Status",
    "Created date",
    "Expiry date",
]


def selected_voucher_ids() -> list[int]:
    raw_values = request.args.getlist("ids")
    ids: list[int] = []
    for raw in raw_values:
        for part in str(raw).split(","):
            parsed = parse_positive_int(part, 0)
            if parsed and parsed not in ids:
                ids.append(parsed)
    return ids


def list_vouchers_for_export(router_id: int, state: dict[str, object], voucher_ids: list[int] | None = None) -> list[sqlite3.Row]:
    if not voucher_ids:
        return list_filtered_vouchers(router_id, state)

    with closing(get_db()) as db:
        params: tuple = (router_id,)
        where = ["router_id = ?"]
        placeholders = ", ".join("?" for _ in voucher_ids)
        where.append(f"id IN ({placeholders})")
        params = (*params, *voucher_ids)
        sql = f"SELECT * FROM vouchers WHERE {' AND '.join(where)} ORDER BY created_at DESC, id DESC"
        return db.execute(sql, params).fetchall()


def voucher_export_row(voucher) -> list[str]:
    return [
        row_value(voucher, "username"),
        row_value(voucher, "password"),
        row_value(voucher, "profile"),
        row_value(voucher, "time_limit"),
        format_money(row_value(voucher, "price", "0.00")),
        row_value(voucher, "status", "unused"),
        row_value(voucher, "created_at"),
        row_value(voucher, "expiry_date"),
    ]


def build_vouchers_pdf(vouchers: list[sqlite3.Row], router) -> bytes:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import landscape, letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise RuntimeError("PDF export needs ReportLab. Run: pip install -r requirements.txt") from exc

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter), rightMargin=24, leftMargin=24, topMargin=24, bottomMargin=24)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("Karte Voucher Export", styles["Title"]),
        Paragraph(f"Router: {row_value(router, 'name', 'Router')} ({row_value(router, 'router_ip')})", styles["Normal"]),
        Spacer(1, 12),
    ]
    table_data = [VOUCHER_EXPORT_COLUMNS]
    table_data.extend(voucher_export_row(voucher) for voucher in vouchers)
    if len(table_data) == 1:
        table_data.append(["No vouchers found", "", "", "", "", "", "", ""])

    table = Table(table_data, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0073e6")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d8e0e8")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7fafc")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(table)
    doc.build(story)
    return buffer.getvalue()


def insert_voucher(voucher: dict[str, str], router_id: int) -> int:
    now = timestamp()
    with closing(get_db()) as db:
        cursor = db.execute(
            """
            INSERT INTO vouchers (
                router_id, package_id, batch_id, created_by, username, password, profile, time_limit,
                price, data_limit, shared_users, status, `comment`, expiry_date, expires_at, removed_at,
                routeros_id, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                router_id,
                parse_positive_int(voucher.get("package_id"), 0) or None,
                parse_positive_int(voucher.get("batch_id"), 0) or None,
                parse_positive_int(voucher.get("created_by"), 0) or current_user_id(),
                voucher["username"],
                voucher["password"],
                voucher["profile"],
                voucher["time_limit"],
                voucher_price_value(voucher),
                voucher.get("data_limit", ""),
                voucher.get("shared_users", "1"),
                voucher.get("status", "unused"),
                voucher.get("comment", ""),
                voucher.get("expiry_date", ""),
                voucher.get("expires_at", ""),
                voucher.get("removed_at", ""),
                voucher.get("routeros_id", ""),
                now,
                now,
            ),
        )
        db.commit()
        return int(cursor.lastrowid)


def update_voucher_row(voucher_id: int, voucher: dict[str, str], router_id: int) -> None:
    with closing(get_db()) as db:
        db.execute(
            """
            UPDATE vouchers
            SET username = ?, password = ?, profile = ?, time_limit = ?, price = ?, data_limit = ?, shared_users = ?,
                status = ?, `comment` = ?, expiry_date = ?, package_id = ?, updated_at = ?
            WHERE id = ? AND router_id = ?
            """,
            (
                voucher["username"],
                voucher["password"],
                voucher["profile"],
                voucher["time_limit"],
                voucher_price_value(voucher),
                voucher.get("data_limit", ""),
                voucher.get("shared_users", "1"),
                voucher.get("status", "unused"),
                voucher.get("comment", ""),
                voucher.get("expiry_date", ""),
                parse_positive_int(voucher.get("package_id"), 0) or None,
                timestamp(),
                voucher_id,
                router_id,
            ),
        )
        db.commit()


def mark_voucher_deleted(voucher_id: int, router_id: int) -> None:
    now = timestamp()
    with closing(get_db()) as db:
        db.execute(
            """
            UPDATE vouchers
            SET status = 'removed', routeros_id = '', online_users = 0, removed_at = ?, updated_at = ?
            WHERE id = ? AND router_id = ?
            """,
            (now, now, voucher_id, router_id),
        )
        db.commit()


def mark_voucher_disabled(voucher_id: int, router_id: int) -> None:
    with closing(get_db()) as db:
        db.execute(
            "UPDATE vouchers SET status = 'disabled', online_users = 0, updated_at = ? WHERE id = ? AND router_id = ?",
            (timestamp(), voucher_id, router_id),
        )
        db.commit()


def renew_voucher_row(voucher_id: int, voucher: dict[str, str], router_id: int) -> None:
    with closing(get_db()) as db:
        db.execute(
            """
            UPDATE vouchers
            SET routeros_id = ?, status = 'active', first_login_ip = '', device_name = '', uptime_used = '', data_used = '',
                online_users = 0, updated_at = ?
            WHERE id = ? AND router_id = ?
            """,
            (voucher.get("routeros_id", ""), timestamp(), voucher_id, router_id),
        )
        db.commit()


def list_routers_for_sync() -> list[sqlite3.Row]:
    with closing(get_db()) as db:
        return db.execute(
            """
            SELECT * FROM routers
            WHERE router_ip <> '' AND router_username <> ''
            ORDER BY id
            """
        ).fetchall()


def list_vouchers_for_sync(router_id: int) -> list[sqlite3.Row]:
    with closing(get_db()) as db:
        return db.execute(
            """
            SELECT * FROM vouchers
            WHERE router_id = ?
            ORDER BY id
            """,
            (router_id,),
        ).fetchall()


def update_voucher_sync_fields(voucher_id: int, router_id: int, fields: dict[str, object]) -> None:
    allowed = {
        "status",
        "activated_at",
        "first_login_mac",
        "first_login_ip",
        "device_name",
        "uptime_used",
        "data_used",
        "online_users",
        "routeros_id",
        "expires_at",
        "removed_at",
        "last_error",
        "retry_count",
    }
    changes = {key: value for key, value in fields.items() if key in allowed}
    if not changes:
        return

    assignments = ", ".join(f"`{key}` = ?" for key in changes)
    params = tuple(changes.values()) + (timestamp(), voucher_id, router_id)
    with closing(get_db()) as db:
        db.execute(
            f"UPDATE vouchers SET {assignments}, updated_at = ? WHERE id = ? AND router_id = ?",
            params,
        )
        db.commit()


def record_voucher_sync_failure(voucher_id: int, router_id: int, error: Exception | str, routeros_id: str = "") -> None:
    message = str(error).strip()[:1000] or "Router removal could not be confirmed."
    with closing(get_db()) as db:
        db.execute(
            """
            UPDATE vouchers
            SET last_error = ?,
                retry_count = COALESCE(retry_count, 0) + 1,
                routeros_id = CASE WHEN ? <> '' THEN ? ELSE routeros_id END,
                updated_at = ?
            WHERE id = ? AND router_id = ?
            """,
            (message, routeros_id, routeros_id, timestamp(), voucher_id, router_id),
        )
        db.commit()


def router_voucher_is_absent(client: "RouterClient", routeros_id: str, username: str) -> bool:
    for remote in client.list_hotspot_users():
        if routeros_id and routeros_item_id(remote) == routeros_id:
            return False
        if str(remote.get("name", "")).strip() == username:
            return False
    return True


def remove_router_voucher_confirmed(client: "RouterClient", routeros_id: str, username: str) -> None:
    client.remove_active_hotspot_sessions(username)
    client.delete_voucher(routeros_id, username)
    if not router_voucher_is_absent(client, routeros_id, username):
        raise RuntimeError("RouterOS still reports the voucher after deletion.")


def reconciliation_issue_details(remote: dict) -> str:
    parts = []
    for key, label in [("profile", "profile"), ("disabled", "disabled"), ("comment", "comment")]:
        value = str(remote.get(key, "")).strip()
        if value:
            parts.append(f"{label}={value}")
    return ", ".join(parts)


def sync_unrecognized_router_users(router_id: int, remote_users: list[dict], known_usernames: set[str]) -> int:
    now = timestamp()
    unknown: dict[str, dict] = {}
    for remote in remote_users:
        username = str(remote.get("name", "")).strip()
        if username and username not in known_usernames:
            unknown[username] = remote

    with closing(get_db()) as db:
        existing_rows = db.execute(
            """
            SELECT * FROM reconciliation_issues
            WHERE router_id = ? AND issue_type = 'router_user_without_voucher'
            """,
            (router_id,),
        ).fetchall()
        existing_by_name = {row_value(row, "remote_name"): row for row in existing_rows}

        for username, remote in unknown.items():
            remote_id = routeros_item_id(remote)
            details = reconciliation_issue_details(remote)
            existing = existing_by_name.get(username)
            if existing:
                status = "open" if row_value(existing, "status") == "resolved" else row_value(existing, "status", "open")
                db.execute(
                    """
                    UPDATE reconciliation_issues
                    SET routeros_id = ?, details = ?, status = ?,
                        occurrence_count = occurrence_count + 1,
                        last_seen_at = ?, resolved_at = ''
                    WHERE id = ?
                    """,
                    (remote_id, details, status, now, int(existing["id"])),
                )
            else:
                db.execute(
                    """
                    INSERT INTO reconciliation_issues (
                        router_id, issue_type, remote_name, routeros_id, details, status,
                        occurrence_count, first_seen_at, last_seen_at, resolved_at
                    )
                    VALUES (?, 'router_user_without_voucher', ?, ?, ?, 'open', 1, ?, ?, '')
                    """,
                    (router_id, username, remote_id, details, now, now),
                )

        for row in existing_rows:
            username = row_value(row, "remote_name")
            if username not in unknown and row_value(row, "status") != "resolved":
                db.execute(
                    """
                    UPDATE reconciliation_issues
                    SET status = 'resolved', resolved_at = ?, last_seen_at = ?
                    WHERE id = ?
                    """,
                    (now, now, int(row["id"])),
                )
        db.commit()

    if unknown:
        LOGGER.warning("unrecognized router users router=%s count=%s", router_id, len(unknown))
    return len(unknown)


def list_reconciliation_issues(router_id: int) -> list[sqlite3.Row]:
    with closing(get_db()) as db:
        return db.execute(
            """
            SELECT * FROM reconciliation_issues
            WHERE router_id = ?
            ORDER BY
                CASE status WHEN 'open' THEN 0 WHEN 'acknowledged' THEN 1 ELSE 2 END,
                last_seen_at DESC,
                id DESC
            """,
            (router_id,),
        ).fetchall()


def get_reconciliation_issue(issue_id: int, router_id: int) -> sqlite3.Row | None:
    with closing(get_db()) as db:
        return db.execute(
            "SELECT * FROM reconciliation_issues WHERE id = ? AND router_id = ?",
            (issue_id, router_id),
        ).fetchone()


def set_reconciliation_issue_status(issue_id: int, router_id: int, status: str) -> None:
    resolved_at = timestamp() if status == "resolved" else ""
    with closing(get_db()) as db:
        db.execute(
            """
            UPDATE reconciliation_issues
            SET status = ?, resolved_at = ?
            WHERE id = ? AND router_id = ?
            """,
            (status, resolved_at, issue_id, router_id),
        )
        db.commit()


def update_router_sync_status(router_id: int, status: str) -> None:
    if not router_id:
        return
    with closing(get_db()) as db:
        db.execute(
            "UPDATE routers SET status = ?, last_synced_at = ?, updated_at = ? WHERE id = ?",
            (status, timestamp(), timestamp(), router_id),
        )
        db.commit()


def voucher_expires_at_from_activation(voucher, activated_at_text: str) -> str:
    activated_at = parse_local_datetime(activated_at_text)
    if not activated_at:
        return ""
    limit_seconds = parse_duration_seconds(row_value(voucher, "time_limit"), zero_as_unlimited=True)
    if limit_seconds is None:
        return ""
    return format_timestamp(activated_at + timedelta(seconds=limit_seconds))


def sync_all_routers() -> dict[str, int]:
    purge_expired_router_sessions()
    summary = {"routers": 0, "checked": 0, "online": 0, "expired": 0}
    for router in list_routers_for_sync():
        try:
            result = sync_router_vouchers(router)
            update_router_sync_status(int(router["id"]), "online")
        except Exception as exc:
            update_router_sync_status(int(row_value(router, "id", "0")), "offline")
            LOGGER.warning("router sync failed router=%s error=%s", row_value(router, "name", row_value(router, "id")), exc)
            continue

        summary["routers"] += 1
        for key in ["checked", "online", "expired"]:
            summary[key] += result[key]
    LOGGER.info("router sync summary routers=%s checked=%s online=%s expired=%s", summary["routers"], summary["checked"], summary["online"], summary["expired"])
    return summary


def sync_router_vouchers(router, settings: dict[str, str] | None = None) -> dict[str, int]:
    return test_and_reconcile_router(router, settings)


def test_and_reconcile_router(router, settings: dict[str, str] | None = None) -> dict[str, int]:
    with voucher_sync_lock() as acquired:
        if not acquired:
            raise RuntimeError("Another voucher sync is already running.")
        client = RouterClient(settings or router_to_settings(router))
        try:
            client.test_connection()
            return sync_router_vouchers_with_client(router, client)
        finally:
            client.close()


@contextmanager
def voucher_sync_lock():
    if not using_mysql():
        acquired = LOCAL_SYNC_LOCK.acquire(timeout=1)
        try:
            yield acquired
        finally:
            if acquired:
                LOCAL_SYNC_LOCK.release()
        return

    with closing(get_db()) as db:
        row = db.execute("SELECT GET_LOCK(?, ?) AS acquired", ("karte_voucher_sync", 1)).fetchone()
        acquired = row_value(row, "acquired", "0") == "1"
        try:
            yield acquired
        finally:
            if acquired:
                db.execute("SELECT RELEASE_LOCK(?)", ("karte_voucher_sync",)).fetchone()


def sync_router_vouchers_with_client(router, client: "RouterClient") -> dict[str, int]:
    router_id = int(row_value(router, "id", "0"))
    remote_users = client.list_hotspot_users()
    active_users = client.list_active_hotspot_users()
    vouchers = list_vouchers_for_sync(router_id)
    remote_by_id = {routeros_item_id(user): user for user in remote_users if routeros_item_id(user)}
    remote_by_name = {str(user.get("name", "")): user for user in remote_users if user.get("name")}
    active_by_name: dict[str, list[dict]] = {}

    for active in active_users:
        username = str(active.get("user") or active.get("name") or "").strip()
        if username:
            active_by_name.setdefault(username, []).append(active)

    for profile_name in sorted({row_value(voucher, "profile") for voucher in vouchers if row_value(voucher, "profile")}):
        try:
            client.enforce_single_user_profile(profile_name)
        except Exception as exc:
            LOGGER.warning(
                "single-device profile enforcement failed router=%s profile=%s error=%s",
                router_id,
                profile_name,
                exc,
            )

    summary = {
        "checked": 0,
        "online": 0,
        "expired": 0,
        "unrecognized": sync_unrecognized_router_users(
            router_id,
            remote_users,
            {row_value(voucher, "username") for voucher in vouchers},
        ),
    }
    for voucher in vouchers:
        summary["checked"] += 1
        username = row_value(voucher, "username")
        remote = remote_by_id.get(row_value(voucher, "routeros_id")) or remote_by_name.get(username)
        active_rows = active_by_name.get(username, [])
        current_status = row_value(voucher, "status", "unused")
        voucher_id = int(row_value(voucher, "id", "0"))

        if current_status in TERMINAL_VOUCHER_STATUSES:
            if not remote:
                if row_value(voucher, "routeros_id") or row_value(voucher, "last_error") or parse_int(row_value(voucher, "retry_count")):
                    update_voucher_sync_fields(
                        voucher_id,
                        router_id,
                        {"routeros_id": "", "online_users": 0, "last_error": "", "retry_count": 0},
                    )
                    audit_log(
                        None,
                        router_id,
                        "voucher",
                        voucher_id,
                        "terminal-confirm",
                        f"Confirmed terminal voucher {username} is absent from router",
                    )
                continue

            remote_id = routeros_item_id(remote)
            try:
                remove_router_voucher_confirmed(client, remote_id, username)
            except Exception as exc:
                record_voucher_sync_failure(voucher_id, router_id, exc, remote_id)
                LOGGER.warning(
                    "terminal voucher removal failed router=%s voucher=%s status=%s error=%s",
                    router_id,
                    username,
                    current_status,
                    exc,
                )
                continue

            update_voucher_sync_fields(
                voucher_id,
                router_id,
                {
                    "status": current_status,
                    "routeros_id": "",
                    "online_users": 0,
                    "removed_at": row_value(voucher, "removed_at") or timestamp(),
                    "last_error": "",
                    "retry_count": 0,
                },
            )
            audit_log(
                None,
                router_id,
                "voucher",
                voucher_id,
                "terminal-remove",
                f"Removed reappeared {current_status} voucher {username} from router",
            )
            continue

        if not remote:
            if current_status == "unused" and not voucher_has_usage_evidence(voucher):
                try:
                    routeros_id = client.create_voucher(voucher_to_dict(voucher))
                    update_voucher_sync_fields(
                        voucher_id,
                        router_id,
                        {"routeros_id": routeros_id or "", "online_users": 0},
                    )
                    audit_log(None, router_id, "voucher", voucher_id, "reconcile", f"Recreated unused voucher {username} on router")
                except Exception as exc:
                    LOGGER.warning("unused voucher recreate failed router=%s voucher=%s error=%s", router_id, username, exc)
                continue

            if parse_int(row_value(voucher, "retry_count")) > 0 and voucher_should_expire(
                voucher,
                row_value(voucher, "uptime_used"),
                parse_int(row_value(voucher, "data_used")),
            ):
                update_voucher_sync_fields(
                    voucher_id,
                    router_id,
                    {
                        "status": "expired",
                        "routeros_id": "",
                        "online_users": 0,
                        "removed_at": timestamp(),
                        "last_error": "",
                        "retry_count": 0,
                    },
                )
                summary["expired"] += 1
                audit_log(None, router_id, "voucher", voucher_id, "expire", f"Confirmed expired voucher {username} is absent from router")
                continue

            update_voucher_sync_fields(
                voucher_id,
                router_id,
                {
                    "status": "removed",
                    "routeros_id": "",
                    "online_users": 0,
                    "removed_at": timestamp(),
                    "last_error": "",
                    "retry_count": 0,
                },
            )
            audit_log(None, router_id, "voucher", voucher_id, "reconcile-remove", f"Confirmed voucher {username} is absent from router")
            continue

        remote_id = routeros_item_id(remote)
        uptime_used = routeros_uptime_used(remote, active_rows)
        data_used = routeros_data_used(remote, active_rows)
        usage_evidence = voucher_has_usage_evidence(voucher, uptime_used, data_used)
        status = next_voucher_status(voucher, remote, active_rows, uptime_used, data_used)
        if current_status == "unused" and not usage_evidence and routeros_disabled(remote):
            try:
                client.enable_voucher(remote_id, username)
            except Exception as exc:
                LOGGER.warning("unused voucher enable failed router=%s voucher=%s error=%s", router_id, username, exc)
            status = "unused"
        elif current_status == "disabled" and not routeros_disabled(remote):
            try:
                client.disable_voucher(remote_id, username)
            except Exception as exc:
                LOGGER.warning("disabled voucher enforcement failed router=%s voucher=%s error=%s", router_id, username, exc)
            status = "disabled"

        fields: dict[str, object] = {
            "routeros_id": remote_id,
            "status": status,
            "online_users": len(active_rows),
            "uptime_used": uptime_used,
            "data_used": str(data_used) if data_used is not None else row_value(voucher, "data_used"),
        }

        if usage_evidence and not row_value(voucher, "activated_at"):
            activated_at = observed_activation_timestamp(voucher, remote, active_rows)
            fields["activated_at"] = activated_at
            fields["expires_at"] = voucher_expires_at_from_activation(voucher, activated_at)

        if active_rows:
            first_active = active_rows[0]
            active_mac = str(first_active.get("mac-address", "")).strip()
            saved_mac = row_value(voucher, "first_login_mac")
            active_macs = {
                str(active.get("mac-address", "")).strip()
                for active in active_rows
                if str(active.get("mac-address", "")).strip()
            }
            conflicting_mac = bool(saved_mac and any(mac != saved_mac for mac in active_macs))
            simultaneous_first_use = bool(not saved_mac and len(active_macs) > 1)
            if conflicting_mac or simultaneous_first_use:
                client.remove_active_hotspot_sessions(username)
                fields["online_users"] = 0
                fields["first_login_mac"] = saved_mac or active_mac
                if active_mac and not saved_mac:
                    try:
                        client.bind_voucher_to_mac(remote_id, username, active_mac)
                    except Exception as exc:
                        LOGGER.warning("voucher mac bind failed router=%s voucher=%s error=%s", router_id, username, exc)
                audit_log(
                    None,
                    router_id,
                    "voucher",
                    voucher_id,
                    "mac-block",
                    f"Blocked simultaneous reuse of {username}; observed MACs={','.join(sorted(active_macs))}",
                )
            else:
                summary["online"] += 1
                activated_at = row_value(voucher, "activated_at") or str(fields.get("activated_at") or timestamp())
                fields["activated_at"] = activated_at
                fields["expires_at"] = row_value(voucher, "expires_at") or voucher_expires_at_from_activation(voucher, activated_at)
                fields["first_login_mac"] = saved_mac or active_mac
                if active_mac and not saved_mac:
                    try:
                        client.bind_voucher_to_mac(remote_id, username, active_mac)
                    except Exception as exc:
                        LOGGER.warning("voucher mac bind failed router=%s voucher=%s error=%s", router_id, username, exc)
            fields["first_login_ip"] = row_value(voucher, "first_login_ip") or str(first_active.get("address") or first_active.get("ip") or "")
            fields["device_name"] = row_value(voucher, "device_name") or str(first_active.get("host-name") or first_active.get("host") or "")
        elif usage_evidence and not row_value(voucher, "first_login_mac"):
            try:
                client.disable_voucher(remote_id, username)
                fields["status"] = "used"
                audit_log(None, router_id, "voucher", voucher_id, "retire", f"Retired used voucher {username} after an unobserved session")
            except Exception as exc:
                LOGGER.warning("used voucher retire failed router=%s voucher=%s error=%s", router_id, username, exc)
        elif row_value(voucher, "activated_at") and not row_value(voucher, "expires_at"):
            fields["expires_at"] = voucher_expires_at_from_activation(voucher, row_value(voucher, "activated_at"))

        effective_voucher = dict(voucher)
        effective_voucher.update(fields)
        if voucher_should_expire(effective_voucher, uptime_used, data_used):
            try:
                remove_router_voucher_confirmed(client, remote_id, username)
            except Exception as exc:
                LOGGER.warning("expired voucher remove failed router=%s voucher=%s error=%s", router_id, username, exc)
                fields.update({"status": current_status, "routeros_id": remote_id})
                update_voucher_sync_fields(voucher_id, router_id, fields)
                record_voucher_sync_failure(voucher_id, router_id, exc, remote_id)
                continue

            fields.update(
                {
                    "status": "expired",
                    "routeros_id": "",
                    "online_users": 0,
                    "removed_at": timestamp(),
                    "last_error": "",
                    "retry_count": 0,
                }
            )
            summary["expired"] += 1
            audit_log(None, router_id, "voucher", voucher_id, "expire", f"Expired voucher {username}")

        update_voucher_sync_fields(voucher_id, router_id, fields)

    refresh_voucher_batch_push_counts(router_id)
    return summary


def next_voucher_status(
    voucher,
    remote: dict,
    active_rows: list[dict],
    uptime_used: str = "",
    data_used: int | None = None,
) -> str:
    current_status = row_value(voucher, "status", "unused")
    if current_status in ["expired", "removed", "deleted"]:
        return current_status
    if current_status == "disabled":
        return "disabled"
    if active_rows:
        return "active"
    if voucher_has_usage_evidence(voucher, uptime_used, data_used):
        return "used"
    return "unused"


def voucher_has_usage_evidence(voucher, uptime_used: str = "", data_used: int | None = None) -> bool:
    if row_value(voucher, "activated_at") or row_value(voucher, "first_login_mac") or row_value(voucher, "first_login_ip"):
        return True
    if row_value(voucher, "status", "unused") in ["active", "used", "expired", "removed", "deleted"]:
        return True
    used_seconds = parse_duration_seconds(uptime_used or row_value(voucher, "uptime_used"), zero_as_unlimited=False)
    if used_seconds and used_seconds > 0:
        return True
    observed_data = data_used if data_used is not None else parse_int(row_value(voucher, "data_used"))
    return bool(observed_data and observed_data > 0)


def observed_activation_timestamp(voucher, remote: dict, active_rows: list[dict]) -> str:
    created_at = parse_local_datetime(row_value(voucher, "created_at")) or datetime.now()
    if not active_rows:
        return format_timestamp(created_at)

    active_uptime = str(active_rows[0].get("uptime", "")).strip()
    active_seconds = parse_duration_seconds(active_uptime, zero_as_unlimited=False) or 0
    remote_seconds = parse_duration_seconds(str(remote.get("uptime", "")), zero_as_unlimited=False) or 0
    if remote_seconds > active_seconds:
        return format_timestamp(created_at)
    return format_timestamp(max(created_at, datetime.now() - timedelta(seconds=active_seconds)))


def voucher_should_expire(voucher, uptime_used: str, data_used: int | None) -> bool:
    status = row_value(voucher, "status")
    if status in ["removed", "deleted"]:
        return False
    if status == "expired":
        return True

    expires_at = parse_local_datetime(row_value(voucher, "expires_at"))
    if expires_at and expires_at <= datetime.now():
        return True

    expiry = parse_local_datetime(row_value(voucher, "expiry_date"))
    if expiry and expiry <= datetime.now():
        return True

    limit_seconds = parse_duration_seconds(row_value(voucher, "time_limit"), zero_as_unlimited=True)
    used_seconds = parse_duration_seconds(uptime_used, zero_as_unlimited=False)
    if limit_seconds is not None and used_seconds is not None and used_seconds >= limit_seconds:
        return True

    data_limit = parse_int(row_value(voucher, "data_limit"))
    if data_limit is not None and data_used is not None and data_used >= data_limit:
        return True

    return False


def refresh_voucher_batch_push_counts(router_id: int) -> None:
    with closing(get_db()) as db:
        batches = db.execute(
            """
            SELECT
                b.id,
                b.pushed_count,
                SUM(CASE WHEN v.routeros_id IS NOT NULL AND v.routeros_id <> '' THEN 1 ELSE 0 END) AS present_count,
                SUM(CASE WHEN v.status = 'unused' AND (v.routeros_id IS NULL OR v.routeros_id = '') THEN 1 ELSE 0 END) AS missing_count
            FROM voucher_batches b
            LEFT JOIN vouchers v ON v.batch_id = b.id AND v.router_id = b.router_id
            WHERE b.router_id = ?
            GROUP BY b.id, b.pushed_count
            """,
            (router_id,),
        ).fetchall()
        for batch in batches:
            pushed = max(parse_int(row_value(batch, "pushed_count", "0")), parse_int(row_value(batch, "present_count", "0")))
            failed = parse_int(row_value(batch, "missing_count", "0"))
            db.execute(
                "UPDATE voucher_batches SET pushed_count = ?, failed_count = ? WHERE id = ? AND router_id = ?",
                (pushed, failed, int(batch["id"]), router_id),
            )
        db.commit()


def start_background_sync(app: Flask) -> None:
    global SYNC_THREAD_STARTED
    if SYNC_THREAD_STARTED:
        return
    if os.environ.get("ENABLE_BACKGROUND_SYNC", "1").strip().lower() in ["0", "false", "no", "off"]:
        return
    if running_under_gunicorn() and not env_flag("ENABLE_BACKGROUND_SYNC_IN_WEB", False):
        return

    SYNC_THREAD_STARTED = True
    thread = threading.Thread(target=background_sync_loop, args=(app,), daemon=True)
    thread.start()


def running_under_gunicorn() -> bool:
    server_software = os.environ.get("SERVER_SOFTWARE", "")
    gunicorn_args = os.environ.get("GUNICORN_CMD_ARGS", "")
    executable = Path(sys.argv[0]).name
    return "gunicorn" in f"{server_software} {gunicorn_args} {executable}".lower()


def background_sync_loop(app: Flask) -> None:
    interval = sync_interval_seconds()
    LOGGER.info("background voucher sync started interval=%ss", interval)
    while True:
        try:
            with app.app_context():
                sync_all_routers()
        except Exception as exc:
            LOGGER.warning("background voucher sync failed error=%s", exc)
        time.sleep(interval)


def sync_interval_seconds() -> int:
    raw = os.environ.get("BACKGROUND_SYNC_SECONDS", "300").strip()
    try:
        seconds = int(raw)
    except ValueError:
        seconds = 300
    return max(60, min(seconds, 300))


def voucher_from_form() -> dict[str, str]:
    return {
        "package_id": request.form.get("package_id", "").strip(),
        "username": request.form.get("username", "").strip(),
        "password": request.form.get("password", "").strip(),
        "profile": request.form.get("profile", "").strip(),
        "time_limit": request.form.get("time_limit", "").strip(),
        "price": request.form.get("price", "0").strip(),
        "data_limit": request.form.get("data_limit", "").strip(),
        "shared_users": request.form.get("shared_users", "1").strip() or "1",
        "expiry_date": request.form.get("expiry_date", "").strip(),
        "status": request.form.get("status", "unused").strip() or "unused",
        "comment": request.form.get("comment", "").strip(),
    }


def apply_package_to_voucher(voucher: dict[str, str], package) -> dict[str, str]:
    updated = dict(voucher)
    updated["package_id"] = row_value(package, "id")
    updated["profile"] = row_value(package, "name")
    updated["time_limit"] = row_value(package, "validity_period", updated.get("time_limit", "1d"))
    updated["price"] = format_money(row_value(package, "price", updated.get("price", "0.00")))
    data_cap = row_value(package, "data_cap")
    updated["data_limit"] = str(parse_int(data_cap) or "") if data_cap else ""
    return updated


def default_hotspot_profile() -> dict[str, str]:
    return {
        "name": "",
        "rate_limit": "",
        "shared_users": "1",
        "session_timeout": "",
        "idle_timeout": "",
    }


def hotspot_profile_from_form() -> dict[str, str]:
    return {
        "name": request.form.get("name", "").strip(),
        "rate_limit": request.form.get("rate_limit", "").strip(),
        "shared_users": request.form.get("shared_users", "1").strip() or "1",
        "session_timeout": request.form.get("session_timeout", "").strip(),
        "idle_timeout": request.form.get("idle_timeout", "").strip(),
    }


def validate_hotspot_profile(profile: dict[str, str]) -> str | None:
    if not profile["name"]:
        return "Please enter a profile name."
    if " " in profile["name"]:
        return "Use a profile name without spaces."
    if profile["shared_users"] and not profile["shared_users"].isdigit():
        return "Shared users must be a number."
    return None


def validate_voucher(voucher: dict[str, str]) -> str | None:
    required = ["username", "password", "profile", "time_limit"]
    if any(not voucher.get(field) for field in required):
        return "Please fill in all voucher fields."
    if parse_price(voucher.get("price")) is None:
        return "Voucher price must be a number and cannot be negative."
    if voucher.get("shared_users", "1") != "1":
        return "Vouchers are limited to one device to prevent reuse."
    expiry = parse_local_datetime(voucher.get("expiry_date", ""))
    if expiry and expiry <= datetime.now():
        return "Expiry date must be in the future."
    if voucher.get("status") not in VOUCHER_STATUSES:
        return "Choose a valid voucher status."
    return None


def validate_router(router: dict[str, str]) -> str | None:
    if not router["name"] or not router["router_ip"] or not router["api_port"] or not router["router_username"]:
        return "Please fill in the router name, IP address, API port, and MikroTik username."
    return validate_router_target(router["router_ip"], router["api_port"])


def validate_router_target(router_ip: str, api_port: str) -> str | None:
    if not api_port.isdigit():
        return "The API port must be a number."
    port = int(api_port)
    if port < 1 or port > 65535:
        return "The API port must be between 1 and 65535."
    if port not in allowed_router_api_ports():
        return "This API port is not allowed. Use a port listed in ROUTER_ALLOWED_PORTS."
    try:
        address = ipaddress.ip_address(router_ip)
    except ValueError:
        return "Enter a router IP address, not a hostname."
    if not any(address in network for network in allowed_router_networks()):
        return "This router IP is outside the private WireGuard or LAN networks allowed by the server."
    return None


def allowed_router_api_ports() -> set[int]:
    ports: set[int] = set()
    for value in os.environ.get("ROUTER_ALLOWED_PORTS", "8728,8729").split(","):
        value = value.strip()
        if value.isdigit() and 1 <= int(value) <= 65535:
            ports.add(int(value))
    return ports or {8728, 8729}


def allowed_router_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    raw = os.environ.get(
        "ROUTER_ALLOWED_NETWORKS",
        "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,fd00::/8",
    )
    networks = []
    for value in raw.split(","):
        value = value.strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            LOGGER.warning("ignored invalid ROUTER_ALLOWED_NETWORKS entry=%s", value)
    return networks


def validate_settings(settings: dict[str, str]) -> str | None:
    router = {
        "name": "Router",
        "router_ip": settings.get("router_ip", ""),
        "api_port": settings.get("api_port", "8728"),
        "router_username": settings.get("router_username", ""),
        "router_password": settings.get("router_password", ""),
    }
    return validate_router(router)


def timestamp() -> str:
    return format_timestamp(datetime.now())


def format_timestamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


def voucher_code_alphabet(character_set: str = "uppercase_numbers", avoid_ambiguous: bool = True) -> str:
    alphabets = {
        "uppercase_numbers": "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "numbers": "0123456789",
    }
    alphabet = alphabets.get(character_set, alphabets["uppercase_numbers"])
    if avoid_ambiguous:
        ambiguous = set("0O1IL")
        alphabet = "".join(character for character in alphabet if character not in ambiguous)
    return alphabet


def random_code(length: int = 8, alphabet: str | None = None) -> str:
    usable_alphabet = alphabet or voucher_code_alphabet()
    return "".join(secrets.choice(usable_alphabet) for _ in range(length))


def parse_local_datetime(value: str) -> datetime | None:
    text = (value or "").strip()
    if not text:
        return None

    for fmt in ["%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"]:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def parse_duration_seconds(value: str, *, zero_as_unlimited: bool) -> int | None:
    text = (value or "").strip().lower()
    if not text or text in ["lifetime", "unlimited"]:
        return None if zero_as_unlimited else 0

    if text.isdigit():
        seconds = int(text)
        return None if zero_as_unlimited and seconds == 0 else seconds

    colon_match = re.fullmatch(r"(?:(\d+)d)?(\d{1,2}):(\d{2}):(\d{2})", text)
    if colon_match:
        days = int(colon_match.group(1) or 0)
        hours = int(colon_match.group(2))
        minutes = int(colon_match.group(3))
        seconds = int(colon_match.group(4))
        total = days * 86400 + hours * 3600 + minutes * 60 + seconds
        return None if zero_as_unlimited and total == 0 else total

    unit_seconds = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    total = 0
    matched = False
    for amount, unit in re.findall(r"(\d+)\s*([wdhms])", text):
        matched = True
        total += int(amount) * unit_seconds[unit]

    if not matched:
        return None
    return None if zero_as_unlimited and total == 0 else total


def format_duration(seconds: int | None) -> str:
    if seconds is None:
        return "Unlimited"
    seconds = max(0, int(seconds))
    if seconds == 0:
        return "0s"

    units = [("w", 604800), ("d", 86400), ("h", 3600), ("m", 60), ("s", 1)]
    parts = []
    remaining = seconds
    for label, unit_seconds in units:
        count, remaining = divmod(remaining, unit_seconds)
        if count:
            parts.append(f"{count}{label}")
        if len(parts) == 2:
            break
    return " ".join(parts)


def parse_int(value) -> int | None:
    text = str(value or "").strip().lower().replace(",", "")
    if not text:
        return None
    if text.isdigit():
        return int(text)

    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([kmgt])b?", text)
    if not match:
        return None

    multiplier = {"k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}[match.group(2)]
    return int(float(match.group(1)) * multiplier)


def parse_price(value) -> Decimal | None:
    text = str(value if value is not None else "").strip().replace(",", "")
    if not text:
        return Decimal("0.00")
    try:
        price = Decimal(text)
    except (InvalidOperation, ValueError):
        return None
    if price < 0:
        return None
    return price.quantize(Decimal("0.01"))


def voucher_price_value(voucher: dict[str, str]) -> str:
    price = parse_price(voucher.get("price"))
    return "0.00" if price is None else str(price)


def format_money(value) -> str:
    price = parse_price(value)
    return "0.00" if price is None else f"{price:.2f}"


def parse_positive_int(value, default: int) -> int:
    try:
        parsed = int(str(value or "").strip())
    except ValueError:
        return default
    return parsed if parsed > 0 else default


def bounded_positive_int(value, default: int, maximum: int) -> int:
    return min(parse_positive_int(value, default), maximum)


def voucher_page_size() -> int:
    requested = parse_positive_int(request.args.get("per_page"), DEFAULT_VOUCHERS_PER_PAGE)
    return requested if requested in VOUCHER_PAGE_SIZES else DEFAULT_VOUCHERS_PER_PAGE


def print_voucher_limit() -> int:
    return bounded_positive_int(request.args.get("limit"), DEFAULT_PRINT_VOUCHER_LIMIT, MAX_PRINT_VOUCHER_LIMIT)


def format_bytes(value: int | None) -> str:
    if value is None:
        return "-"
    size = float(max(0, value))
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}".replace(".0 ", " ")
        size /= 1024
    return f"{value} B"


def voucher_time_remaining(voucher) -> str:
    limit = parse_duration_seconds(row_value(voucher, "time_limit"), zero_as_unlimited=True)
    if limit is None:
        return "Unlimited"
    used = parse_duration_seconds(row_value(voucher, "uptime_used"), zero_as_unlimited=False) or 0
    return format_duration(max(0, limit - used))


def voucher_data_remaining(voucher) -> str:
    limit = parse_int(row_value(voucher, "data_limit"))
    if limit is None:
        return "Unlimited"
    used = parse_int(row_value(voucher, "data_used")) or 0
    return format_bytes(max(0, limit - used))


def routeros_item_id(item: dict) -> str:
    return str(item.get("id") or item.get(".id") or item.get("=.id") or "").strip()


def routeros_disabled(item: dict) -> bool:
    return str(item.get("disabled", "")).strip().lower() in ["yes", "true", "1"]


def routeros_uptime_used(remote: dict, active_rows: list[dict]) -> str:
    for item in [remote, *active_rows]:
        uptime = str(item.get("uptime", "")).strip()
        if uptime:
            return uptime
    return ""


def routeros_data_used(remote: dict, active_rows: list[dict]) -> int | None:
    totals = [routeros_bytes_total(active) for active in active_rows]
    totals = [total for total in totals if total is not None]
    if totals:
        return sum(totals)
    return routeros_bytes_total(remote)


def routeros_bytes_total(item: dict) -> int | None:
    total = parse_int(item.get("bytes-total") or item.get("bytes"))
    if total is not None:
        return total

    bytes_in = parse_int(item.get("bytes-in")) or 0
    bytes_out = parse_int(item.get("bytes-out")) or 0
    if bytes_in or bytes_out:
        return bytes_in + bytes_out
    return None


def active_hotspot_user_row(active: dict, remote: dict | None = None) -> dict[str, object]:
    username = str(active.get("user") or active.get("name") or "").strip()
    bytes_in = parse_int(active.get("bytes-in"))
    bytes_out = parse_int(active.get("bytes-out"))
    data_total = routeros_bytes_total(active)

    if data_total is None and remote:
        data_total = routeros_bytes_total(remote)

    return {
        "id": routeros_item_id(active),
        "username": username or "-",
        "ip_address": str(active.get("address") or active.get("ip") or "").strip() or "-",
        "mac_address": str(active.get("mac-address") or "").strip() or "-",
        "uptime": str(active.get("uptime") or "").strip() or "-",
        "idle_time": str(active.get("idle-time") or "").strip() or "-",
        "session_time_left": str(active.get("session-time-left") or "").strip() or "-",
        "data_in": bytes_in,
        "data_in_label": format_bytes(bytes_in),
        "data_out": bytes_out,
        "data_out_label": format_bytes(bytes_out),
        "data_total": data_total,
        "data_total_label": format_bytes(data_total),
        "profile": str((remote or {}).get("profile") or active.get("profile") or "").strip() or "-",
        "server": str(active.get("server") or "").strip() or "-",
        "login_by": str(active.get("login-by") or "").strip() or "-",
    }


def router_setup_options_from_request(settings: dict[str, str]) -> dict[str, str]:
    defaults = {
        "api_port": adoption_env("KARTE_ADOPTION_API_PORT", settings.get("api_port") or "8728"),
        "api_user": adoption_env("KARTE_ADOPTION_API_USER", settings.get("router_username") or "karte-api"),
        "api_password": settings.get("router_password") or secrets.token_urlsafe(18),
        "limit_api_to_wireguard": adoption_env("KARTE_ADOPTION_LIMIT_API", "yes"),
        "wg_interface": adoption_env("KARTE_ADOPTION_WG_INTERFACE", "karte-wg"),
        "wg_router_address": adoption_env("KARTE_ADOPTION_ROUTER_ADDRESS", "10.10.10.2/32"),
        "wg_listen_port": adoption_env("KARTE_ADOPTION_ROUTER_LISTEN_PORT", "13231"),
        "wg_mtu": adoption_env("KARTE_ADOPTION_WG_MTU", "1420"),
        "wg_server_public_key": adoption_env(
            "KARTE_ADOPTION_SERVER_PUBLIC_KEY",
            "PASTE_VPS_WIREGUARD_PUBLIC_KEY",
        ),
        "wg_server_endpoint_address": adoption_env(
            "KARTE_ADOPTION_SERVER_ENDPOINT",
            "your-vps-public-ip",
        ),
        "wg_server_endpoint_port": adoption_env("KARTE_ADOPTION_SERVER_PORT", "51820"),
        "wg_server_allowed_address": adoption_env("KARTE_ADOPTION_SERVER_ADDRESS", "10.10.10.1/32"),
        "wg_persistent_keepalive": adoption_env("KARTE_ADOPTION_KEEPALIVE", "25s"),
    }

    if request.method != "POST":
        return defaults

    return {
        key: request.form.get(key, value).strip() or value
        for key, value in defaults.items()
    }


def adoption_env(name: str, fallback: str) -> str:
    return os.environ.get(name, "").strip() or fallback


def routeros_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_router_setup_script(options: dict[str, str]) -> str:
    values = {key: routeros_quote(value) for key, value in options.items()}
    wireguard_section = build_wireguard_setup_section(options, values)
    api_limit_section = build_api_limit_section(options)
    done_message = (
        f'Add this router in Karte using IP {strip_cidr(options["wg_router_address"])}, '
        f'API port {options["api_port"]}, user {options["api_user"]}, and the API password from this page.'
    )

    return f""":put "Karte router adoption started"

# RouterOS 7 is required for WireGuard.
# This adoption script preserves existing WAN, LAN, bridge, Wi-Fi,
# DHCP, hotspot, NAT, and routing configuration.
:local apiPort {values['api_port']}
:local apiUser {values['api_user']}
:local apiPassword {values['api_password']}
:local apiGroup "karte-api"
:local apiService "api"

:local wgInterface {values['wg_interface']}
:local wgRouterAddress {values['wg_router_address']}
:local wgListenPort {values['wg_listen_port']}
:local wgMtu {values['wg_mtu']}
:local wgServerPublicKey {values['wg_server_public_key']}
:local wgServerEndpointAddress {values['wg_server_endpoint_address']}
:local wgServerEndpointPort {values['wg_server_endpoint_port']}
:local wgServerAllowedAddress {values['wg_server_allowed_address']}
:local wgPersistentKeepalive {values['wg_persistent_keepalive']}

:put "Creating Karte WireGuard management tunnel"
{wireguard_section}

:put "Enabling RouterOS API for Karte"
/ip service set [find name=$apiService] disabled=no port=[:tonum $apiPort]
{api_limit_section}

:put "Allowing Karte API traffic through the router firewall"
:if ([:len [/ip firewall filter find comment="Karte WireGuard API access"]] = 0) do={{
    /ip firewall filter add chain=input action=accept protocol=tcp in-interface=$wgInterface src-address=$wgServerAllowedAddress dst-port=[:tonum $apiPort] place-before=0 comment="Karte WireGuard API access"
}}

:put "Creating dedicated Karte API user"
:if ([:len [/user group find name=$apiGroup]] = 0) do={{
    /user group add name=$apiGroup policy=read,write,api,test
}}
:if ([:len [/user find name=$apiUser]] = 0) do={{
    /user add name=$apiUser password=$apiPassword group=$apiGroup comment="Karte API user"
}} else={{
    /user set [find name=$apiUser] password=$apiPassword group=$apiGroup disabled=no
}}

:put "Karte router adoption finished"
:put "{routeros_quote(done_message)[1:-1]}"
"""


def strip_cidr(value: str) -> str:
    return value.split("/", 1)[0].strip()


def build_wireguard_setup_section(options: dict[str, str], values: dict[str, str]) -> str:
    router_allowed_address = options["wg_router_address"]
    return f""":if ([:len [/interface wireguard find name=$wgInterface]] = 0) do={{
    /interface wireguard add name=$wgInterface listen-port=[:tonum $wgListenPort] mtu=[:tonum $wgMtu] comment="Karte RouterOS Management System VPS WireGuard"
}} else={{
    /interface wireguard set [find name=$wgInterface] listen-port=[:tonum $wgListenPort] mtu=[:tonum $wgMtu] disabled=no
}}

:if ([:len [/ip address find interface=$wgInterface address=$wgRouterAddress]] = 0) do={{
    /ip address add interface=$wgInterface address=$wgRouterAddress comment="Karte RouterOS Management System WireGuard address"
}}

:if (($wgServerPublicKey = "") or ($wgServerPublicKey = "PASTE_VPS_WIREGUARD_PUBLIC_KEY")) do={{
    :put "WireGuard peer was not added. Set the VPS WireGuard public key on the app page first."
}} else={{
    :if ([:len [/interface wireguard peers find interface=$wgInterface public-key=$wgServerPublicKey]] = 0) do={{
        /interface wireguard peers add interface=$wgInterface public-key=$wgServerPublicKey endpoint-address=$wgServerEndpointAddress endpoint-port=[:tonum $wgServerEndpointPort] allowed-address=$wgServerAllowedAddress persistent-keepalive=$wgPersistentKeepalive comment="Karte RouterOS Management System VPS"
    }} else={{
        /interface wireguard peers set [find interface=$wgInterface public-key=$wgServerPublicKey] endpoint-address=$wgServerEndpointAddress endpoint-port=[:tonum $wgServerEndpointPort] allowed-address=$wgServerAllowedAddress persistent-keepalive=$wgPersistentKeepalive disabled=no
    }}
}}

:local routerWireGuardPublicKey [/interface wireguard get [find name=$wgInterface] public-key]
:put ("Router WireGuard public key: " . $routerWireGuardPublicKey)
:put "Add this peer on the VPS WireGuard server:"
:put "[Peer]"
:put ("PublicKey = " . $routerWireGuardPublicKey)
:put "AllowedIPs = {router_allowed_address}"
"""


def build_api_limit_section(options: dict[str, str]) -> str:
    if options.get("limit_api_to_wireguard") == "yes":
        return "/ip service set [find name=$apiService] address=$wgServerAllowedAddress"
    return ':put "API is not limited to WireGuard by this script."'


def discover_routerboard(api_port: int = 8728) -> dict[str, object] | None:
    candidates: dict[str, dict[str, object]] = {}

    def remember(ip: str, source: str) -> None:
        if not is_usable_ipv4(ip):
            return
        candidates.setdefault(ip, {"ip": ip, "source": source, "api_open": False})

    for ip in get_default_gateways():
        remember(ip, "Windows default gateway")

    for ip in listen_for_mikrotik_neighbors():
        remember(ip, "MikroTik neighbor discovery")

    for candidate in candidates.values():
        if tcp_port_open(str(candidate["ip"]), api_port, timeout=0.35):
            candidate["api_open"] = True
            return candidate

    for ip in scan_local_subnets_for_api(api_port):
        return {"ip": ip, "source": f"local network API port {api_port} scan", "api_open": True}

    return next(iter(candidates.values()), None)


def get_default_gateways() -> list[str]:
    output = run_command(["ipconfig"], timeout=3)
    if not output:
        return []

    gateways: list[str] = []
    expecting_gateway = False

    for line in output.splitlines():
        if "Default Gateway" in line:
            expecting_gateway = True
            gateways.extend(extract_ipv4s(line))
            continue

        if expecting_gateway:
            ips = extract_ipv4s(line)
            if ips:
                gateways.extend(ips)
                continue
            if line.strip():
                expecting_gateway = False

    return unique_ipv4s(gateways)


def listen_for_mikrotik_neighbors(timeout: float = 2.2) -> list[str]:
    found: list[str] = []
    deadline = time.monotonic() + timeout

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", 5678))
            sock.settimeout(0.35)

            while time.monotonic() < deadline:
                try:
                    data, address = sock.recvfrom(4096)
                except TimeoutError:
                    continue
                except OSError:
                    break

                text = data.decode("latin1", errors="ignore")
                if "MikroTik" in text or "RouterOS" in text or "RouterBOARD" in text:
                    found.append(address[0])
    except OSError:
        return []

    return unique_ipv4s(found)


def scan_local_subnets_for_api(api_port: int) -> list[str]:
    hosts: list[str] = []
    for network in local_ipv4_networks():
        hosts.extend(str(host) for host in network.hosts())

    hosts = unique_ipv4s(hosts)[:1024]
    if not hosts:
        return []

    found: list[str] = []
    with ThreadPoolExecutor(max_workers=96) as executor:
        futures = {executor.submit(tcp_port_open, host, api_port, 0.22): host for host in hosts}
        for future in as_completed(futures):
            if future.result():
                found.append(futures[future])
                if len(found) >= 5:
                    break

    return found


def local_ipv4_networks() -> list[ipaddress.IPv4Network]:
    networks: list[ipaddress.IPv4Network] = []
    for ip in local_ipv4_addresses():
        if is_usable_ipv4(ip):
            networks.append(ipaddress.ip_network(f"{ip}/24", strict=False))

    unique: dict[str, ipaddress.IPv4Network] = {}
    for network in networks:
        if network.is_private:
            unique[str(network)] = network

    return list(unique.values())[:4]


def local_ipv4_addresses() -> list[str]:
    addresses: list[str] = []

    try:
        for result in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addresses.append(result[4][0])
    except OSError:
        pass

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            addresses.append(sock.getsockname()[0])
    except OSError:
        pass

    output = run_command(["ipconfig"], timeout=3)
    if output:
        for line in output.splitlines():
            if "IPv4" in line:
                addresses.extend(extract_ipv4s(line))

    return unique_ipv4s(addresses)


def tcp_port_open(ip: str, port: int, timeout: float = 0.3) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def run_command(command: list[str], timeout: float = 3) -> str:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except (OSError, subprocess.SubprocessError):
        return ""

    return completed.stdout


def extract_ipv4s(text: str) -> list[str]:
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)


def unique_ipv4s(ips: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()

    for ip in ips:
        if ip in seen or not is_usable_ipv4(ip):
            continue
        unique.append(ip)
        seen.add(ip)

    return unique


def is_usable_ipv4(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return bool(address.version == 4 and not address.is_loopback and not address.is_link_local and not address.is_multicast)


class RouterClient:
    def __init__(self, settings: dict[str, str]):
        self.settings = settings
        self._api = None
        self._pool = None
        self._single_user_profiles: set[str] = set()
        if has_request_context():
            clients = getattr(g, "router_clients", [])
            clients.append(self)
            g.router_clients = clients

    def close(self) -> None:
        if self._pool is not None:
            try:
                self._pool.disconnect()
            except Exception:
                pass
        self._pool = None
        self._api = None

    def configured(self) -> bool:
        return bool(
            self.settings.get("router_ip")
            and self.settings.get("api_port")
            and self.settings.get("router_username")
        )

    def test_connection(self):
        return self.resource("/system/resource").get()

    def list_hotspot_users(self):
        return self.resource("/ip/hotspot/user").get()

    def list_active_hotspot_users(self):
        return self.resource("/ip/hotspot/active").get()

    def connected_hotspot_users(self) -> list[dict[str, object]]:
        active_users = self.list_active_hotspot_users()
        remote_by_name = {}

        try:
            remote_by_name = {
                str(user.get("name", "")).strip(): user
                for user in self.list_hotspot_users()
                if str(user.get("name", "")).strip()
            }
        except Exception:
            remote_by_name = {}

        connected = []
        for active in active_users:
            username = str(active.get("user") or active.get("name") or "").strip()
            connected.append(active_hotspot_user_row(active, remote_by_name.get(username)))

        return sorted(connected, key=lambda item: str(item["username"]).lower())

    def list_hotspot_profiles(self):
        profiles = self.resource("/ip/hotspot/user/profile").get()
        return sorted(profiles, key=lambda item: str(item.get("name", "")).lower())

    def find_hotspot_profile(self, name: str):
        for profile in self.list_hotspot_profiles():
            if profile.get("name") == name:
                return profile
        return None

    def create_hotspot_profile(self, profile: dict[str, str]) -> None:
        self.resource("/ip/hotspot/user/profile").add(**self.hotspot_profile_params(profile))

    def ensure_hotspot_profile(self, profile: dict[str, str]) -> None:
        existing = self.find_hotspot_profile(profile["name"])
        params = self.hotspot_profile_params(profile)
        if existing and routeros_item_id(existing):
            params.pop("name", None)
            if params:
                self.resource("/ip/hotspot/user/profile").set(id=routeros_item_id(existing), **params)
            return
        self.resource("/ip/hotspot/user/profile").add(**params)

    def enforce_single_user_profile(self, name: str) -> None:
        profile_name = str(name or "").strip()
        if not profile_name or profile_name in self._single_user_profiles:
            return
        existing = self.find_hotspot_profile(profile_name)
        if not existing or not routeros_item_id(existing):
            raise RuntimeError(f"Hotspot profile {profile_name} was not found on the router.")
        if str(existing.get("shared-users", "1")).strip() != "1":
            self.resource("/ip/hotspot/user/profile").set(
                id=routeros_item_id(existing),
                **{"shared-users": "1"},
            )
        self._single_user_profiles.add(profile_name)

    def hotspot_profile_params(self, profile: dict[str, str]) -> dict[str, str]:
        params = {"name": profile["name"]}
        optional_fields = {
            "rate_limit": "rate-limit",
            "shared_users": "shared-users",
            "session_timeout": "session-timeout",
            "idle_timeout": "idle-timeout",
        }

        for form_key, routeros_key in optional_fields.items():
            value = profile.get(form_key, "").strip()
            if value:
                params[routeros_key] = value

        return params

    def create_voucher(self, voucher: dict[str, str]) -> str:
        self.enforce_single_user_profile(voucher["profile"])
        user_resource = self.resource("/ip/hotspot/user")
        user_resource.add(**self.voucher_params(voucher))
        return self.find_remote_id(voucher["username"]) or ""

    def update_voucher(self, routeros_id: str | None, old_username: str, voucher: dict[str, str]) -> str:
        self.enforce_single_user_profile(voucher["profile"])
        remote = self.find_hotspot_user(routeros_id, old_username)
        if not remote or not routeros_item_id(remote):
            raise RuntimeError("The voucher was not found on the MikroTik router.")

        remote_id = routeros_item_id(remote)
        self.resource("/ip/hotspot/user").set(id=remote_id, **self.voucher_params(voucher))
        return remote_id

    def disable_voucher(self, routeros_id: str | None, username: str) -> None:
        remote = self.find_hotspot_user(routeros_id, username)
        if not remote or not routeros_item_id(remote):
            raise RuntimeError("The voucher was not found on the MikroTik router.")
        self.resource("/ip/hotspot/user").set(id=routeros_item_id(remote), disabled="yes")

    def enable_voucher(self, routeros_id: str | None, username: str) -> None:
        remote = self.find_hotspot_user(routeros_id, username)
        if not remote or not routeros_item_id(remote):
            raise RuntimeError("The voucher was not found on the MikroTik router.")
        self.resource("/ip/hotspot/user").set(id=routeros_item_id(remote), disabled="no")

    def renew_voucher(self, voucher: dict[str, str]) -> str:
        remote = self.find_hotspot_user(voucher.get("routeros_id"), voucher["username"])
        if remote and routeros_item_id(remote):
            remote_id = routeros_item_id(remote)
            self.resource("/ip/hotspot/user").set(id=remote_id, **self.voucher_params(voucher))
            return remote_id
        return self.create_voucher(voucher)

    def voucher_params(self, voucher: dict[str, str]) -> dict[str, str]:
        params = {
            "name": voucher["username"],
            "password": voucher["password"],
            "profile": voucher["profile"],
            "disabled": "yes" if voucher.get("status") == "disabled" else "no",
            "limit-uptime": voucher["time_limit"],
            "limit-bytes-total": voucher.get("data_limit", ""),
            "comment": voucher.get("comment", ""),
        }
        return params

    def remove_active_hotspot_sessions(self, username: str) -> None:
        active_resource = self.resource("/ip/hotspot/active")
        for active in active_resource.get():
            active_user = str(active.get("user") or active.get("name") or "").strip()
            if active_user == username and routeros_item_id(active):
                active_resource.remove(id=routeros_item_id(active))

    def bind_voucher_to_mac(self, routeros_id: str | None, username: str, mac_address: str) -> None:
        if not mac_address:
            return
        remote = self.find_hotspot_user(routeros_id, username)
        if not remote or not routeros_item_id(remote):
            return
        self.resource("/ip/hotspot/user").set(id=routeros_item_id(remote), **{"mac-address": mac_address})

    def delete_voucher(self, routeros_id: str | None, username: str) -> None:
        remote = self.find_hotspot_user(routeros_id, username)
        if not remote or not routeros_item_id(remote):
            raise RuntimeError("The voucher was not found on the MikroTik router.")

        self.resource("/ip/hotspot/user").remove(id=routeros_item_id(remote))

    def find_remote_id(self, username: str) -> str | None:
        remote = self.find_hotspot_user(None, username)
        return routeros_item_id(remote) if remote else None

    def find_hotspot_user(self, routeros_id: str | None, username: str):
        users = self.resource("/ip/hotspot/user").get()

        for user in users:
            if routeros_id and routeros_item_id(user) == routeros_id:
                return user

        for user in users:
            if user.get("name") == username:
                return user

        return None

    def resource(self, path: str):
        return self.api().get_resource(path)

    def api(self):
        if self._api:
            return self._api

        if routeros_api is None:
            raise RuntimeError("RouterOS API package is not installed. Run: pip install -r requirements.txt")

        if not self.configured():
            raise RuntimeError("Router settings are missing. Open Router Settings first.")

        target_error = validate_router_target(self.settings["router_ip"], self.settings["api_port"])
        if target_error:
            raise RuntimeError(target_error)

        port = int(self.settings["api_port"])
        use_ssl = port == 8729 or env_flag("ROUTER_API_USE_SSL", False)
        pool = routeros_api.RouterOsApiPool(
            self.settings["router_ip"],
            username=self.settings["router_username"],
            password=self.settings.get("router_password", ""),
            port=port,
            plaintext_login=True,
            use_ssl=use_ssl,
            ssl_verify=env_flag("ROUTER_API_SSL_VERIFY", is_production()),
            ssl_verify_hostname=env_flag("ROUTER_API_SSL_VERIFY_HOSTNAME", is_production()),
        )
        try:
            pool.socket_timeout = max(2.0, min(float(os.environ.get("ROUTER_API_TIMEOUT", "8")), 30.0))
        except ValueError:
            pool.socket_timeout = 8.0
        self._pool = pool
        self._api = pool.get_api()
        return self._api


app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("APP_HOST", "127.0.0.1"),
        port=int(os.environ.get("APP_PORT", "8008")),
        debug=os.environ.get("FLASK_DEBUG") == "1",
        use_reloader=False,
    )
