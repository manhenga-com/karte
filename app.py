from __future__ import annotations

import os
import ipaddress
import re
import secrets
import socket
import sqlite3
import subprocess
import threading
import time
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

try:
    import routeros_api
except ImportError:  # The app shows a friendly setup error when router actions are used.
    routeros_api = None

try:
    from mysql import connector as mysql_connector
except ImportError:  # MySQL is optional unless DB_ENGINE=mysql is selected.
    mysql_connector = None


BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR / "storage"
DATABASE = STORAGE_DIR / "database.sqlite"
SECRET_KEY_PATH = STORAGE_DIR / "secret_key.txt"
ROUTER_SESSION_SECONDS = 30 * 60
TRIAL_DAYS = 30
TRIAL_ROUTER_LIMIT = 1
UPGRADE_ROUTER_LIMITS = [3, 10, 25, 100]
SYNC_THREAD_STARTED = False


def create_app() -> Flask:
    app = Flask(__name__)
    STORAGE_DIR.mkdir(exist_ok=True)
    load_env_file()
    validate_startup_config()
    app.config["SECRET_KEY"] = load_secret_key()
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=ROUTER_SESSION_SECONDS)
    app.config["SESSION_REFRESH_EACH_REQUEST"] = False
    configure_http_settings(app)
    init_db()
    start_background_sync(app)

    public_endpoints = {"account_login", "account_register", "health", "healthz", "manifest", "service_worker", "static"}
    router_optional_endpoints = {
        "home",
        "login",
        "logout",
        "routers",
        "routers_add",
        "routers_edit",
        "routers_use",
        "routers_delete",
        "account_logout",
        "account_upgrade",
    }

    @app.before_request
    def require_app_and_router_login():
        if request.endpoint in public_endpoints or request.endpoint is None:
            return None

        if not current_user_id():
            clear_router_session()
            return redirect(url_for("account_login", next=request.full_path if request.query_string else request.path))

        if trial_has_expired() and request.endpoint not in {"home", "routers", "routers_delete", "logout", "account_logout", "account_upgrade"}:
            clear_router_session()
            flash("Your 30-day free trial has ended. Router management is disabled.", "warning")
            return redirect(url_for("routers"))

        if request.endpoint in router_optional_endpoints:
            return None

        if router_session_active():
            return None

        had_login = bool(session.get("router_session_token"))
        clear_router_session()
        if had_login:
            flash("Router login expired after 30 minutes. Please login again.", "warning")
        return redirect(url_for("login", next=request.full_path if request.query_string else request.path))

    @app.after_request
    def prevent_dynamic_page_cache(response):
        if request.endpoint not in {"static", "manifest", "service_worker"}:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

    @app.context_processor
    def inject_active_router():
        return {
            "active_router": get_active_router() if router_session_active() else None,
            "current_user": current_user(),
            "session_minutes_left": session_minutes_left(),
            "trial_status": current_trial_status(),
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

    @app.route("/")
    def home():
        router = get_active_router()
        voucher_count = count_vouchers(router["id"]) if router else 0
        return render_template("home.html", voucher_count=voucher_count)

    @app.route("/health")
    def health():
        return "ok router-discovery setup-script-v1 multi-router-v1 vps-wireguard-v1 winbox-login-v1 mysql-v1 saas-v1 voucher-sync-v1 trial-v1 upgrade-v1 vps-deploy-v1 active-users-v1\n", 200, {"Content-Type": "text/plain; charset=utf-8"}

    @app.route("/healthz")
    def healthz():
        with closing(get_db()) as db:
            db.execute("SELECT 1").fetchone()
        return "ok\n", 200, {"Content-Type": "text/plain; charset=utf-8"}

    @app.route("/account/login", methods=["GET", "POST"])
    def account_login():
        next_url = request.values.get("next", "")

        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            user = find_app_user_by_email(email)

            if not user or not check_password_hash(user["password_hash"], password):
                flash("Email or password is incorrect.", "danger")
                return render_template("account_login.html", email=email, next_url=next_url, has_users=app_user_count() > 0)

            login_app_user(user)
            flash("Signed in to Karte.", "success")
            return redirect(safe_next_url(next_url) or url_for("home"))

        return render_template("account_login.html", email="", next_url=next_url, has_users=app_user_count() > 0)

    @app.route("/account/register", methods=["GET", "POST"])
    def account_register():
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")

            error = validate_app_user(name, email, password)
            if error:
                flash(error, "danger")
                return render_template("account_register.html", name=name, email=email)

            try:
                user_id = create_app_user(name, email, password)
            except ValueError as exc:
                flash(str(exc), "danger")
                return render_template("account_register.html", name=name, email=email)

            user = get_app_user(user_id)
            login_app_user(user)
            claim_unowned_routers(user_id)
            flash("Account created. You can now connect a router.", "success")
            return redirect(url_for("home"))

        return render_template("account_register.html", name="", email="")

    @app.route("/account/logout", methods=["GET", "POST"])
    def account_logout():
        clear_router_session()
        session.clear()
        flash("Signed out of Karte.", "success")
        return redirect(url_for("account_login"))

    @app.route("/account/upgrade", methods=["GET", "POST"])
    def account_upgrade():
        user = current_user()
        if not user:
            return redirect(url_for("account_login"))

        if request.method == "POST":
            selected_limit = parse_positive_int(request.form.get("router_limit"), 0)
            if selected_limit not in UPGRADE_ROUTER_LIMITS:
                flash("Choose a valid router limit.", "danger")
                return render_template("account_upgrade.html", options=UPGRADE_ROUTER_LIMITS)

            upgrade_account_router_limit(int(user["id"]), selected_limit)
            flash(f"Upgrade applied. You can now add up to {selected_limit} routers.", "success")
            return redirect(url_for("routers"))

        return render_template("account_upgrade.html", options=UPGRADE_ROUTER_LIMITS)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        router = login_defaults()
        next_url = request.values.get("next", "")

        if request.method == "POST":
            data = router_from_form(router)
            error = validate_router(data)
            if error:
                flash(error, "danger")
                return render_template("login.html", router=data, next_url=next_url)

            if not find_router_by_login(data):
                limit_error = trial_router_limit_error()
                if limit_error:
                    flash(limit_error, "warning")
                    return render_template("login.html", router=data, next_url=next_url)

            try:
                RouterClient(data).test_connection()
            except Exception as exc:
                flash(f"Router login failed: {exc}", "danger")
                return render_template("login.html", router=data, next_url=next_url)

            try:
                router_id = save_login_router(data)
            except ValueError as exc:
                flash(str(exc), "warning")
                return render_template("login.html", router=data, next_url=next_url)
            start_router_session(router_id, data)
            flash("Router login successful. Session will expire in 30 minutes.", "success")
            return redirect(safe_next_url(next_url) or url_for("home"))

        return render_template("login.html", router=router, next_url=next_url)

    @app.route("/logout")
    def logout():
        clear_router_session()
        flash("Logged out from the router session.", "success")
        return redirect(url_for("login"))

    @app.route("/settings", methods=["GET", "POST"])
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
                    RouterClient(data).test_connection()
                except Exception as exc:
                    flash(f"Settings saved, but connection failed: {exc}", "danger")
                    return redirect(url_for("settings"))

                flash("Settings saved. Router connection works.", "success")
            else:
                flash("Router settings saved.", "success")

            return redirect(url_for("settings"))

        return render_template("settings.html", settings=router)

    @app.route("/settings/discover")
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
    def routers():
        return render_template("routers.html", routers=list_routers())

    @app.route("/routers/add", methods=["GET", "POST"])
    def routers_add():
        limit_error = trial_router_limit_error()
        if limit_error:
            flash(limit_error, "warning")
            return redirect(url_for("routers"))

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

            if request.form.get("action") == "test":
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
            start_router_session(router_id, data)
            flash("Router saved and selected.", "success")
            return redirect(url_for("vouchers"))

        return render_template("router_form.html", router=router, mode="add")

    @app.route("/routers/<int:router_id>/edit", methods=["GET", "POST"])
    def routers_edit(router_id: int):
        router = get_router(router_id)
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

            if request.form.get("action") == "test":
                try:
                    RouterClient(data).test_connection()
                except Exception as exc:
                    flash(f"Router login failed: {exc}", "danger")
                    data["id"] = router_id
                    return render_template("router_form.html", router=data, mode="edit")

            update_router(router_id, data)
            start_router_session(router_id, data)
            flash("Router saved and selected.", "success")
            return redirect(url_for("routers"))

        return render_template("router_form.html", router=router, mode="edit")

    @app.post("/routers/<int:router_id>/use")
    def routers_use(router_id: int):
        router = get_router(router_id)
        if not router:
            flash("Router not found.", "warning")
        else:
            start_router_session(router_id, router)
            flash(f"Using router {router['name']}.", "success")
        return redirect(url_for("routers"))

    @app.post("/routers/<int:router_id>/delete")
    def routers_delete(router_id: int):
        router = get_router(router_id)
        if not router:
            flash("Router not found.", "warning")
            return redirect(url_for("routers"))

        delete_router(router_id)
        if session.get("router_id") == router_id:
            clear_router_session()
        flash(f"Deleted router {router['name']}.", "success")
        return redirect(url_for("routers"))

    @app.route("/router-setup-script", methods=["GET", "POST"])
    def router_setup_script():
        active_router = get_active_router()
        settings_data = active_router_settings(active_router) if active_router else get_settings()
        options = router_setup_options_from_request(settings_data)
        script = build_router_setup_script(options)
        return render_template("router_setup_script.html", options=options, script=script)

    @app.route("/profiles", methods=["GET", "POST"])
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

    @app.route("/hotspot/active")
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

    @app.route("/vouchers")
    def vouchers():
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))
        selected_status = request.args.get("status", "all")
        if selected_status not in ["all", *VOUCHER_STATUSES]:
            selected_status = "all"
        return render_template(
            "vouchers.html",
            vouchers=list_vouchers(router["id"], selected_status),
            counts=voucher_status_counts(router["id"]),
            statuses=VOUCHER_STATUSES,
            selected_status=selected_status,
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

        if request.method == "POST":
            data = voucher_from_form()
            error = validate_voucher(data)
            if error:
                flash(error, "danger")
                return render_template("voucher_form.html", voucher=data, mode="create", profile_names=profile_names)

            if get_voucher_by_username(data["username"], router["id"]):
                flash("This router already has a local voucher with this username.", "danger")
                return render_template("voucher_form.html", voucher=data, mode="create", profile_names=profile_names)

            try:
                routeros_id = RouterClient(active_router_settings(router)).create_voucher(data)
                data["routeros_id"] = routeros_id or ""
                voucher_id = insert_voucher(data, router["id"])
            except Exception as exc:
                flash(f"Could not create voucher on MikroTik router: {exc}", "danger")
                return render_template("voucher_form.html", voucher=data, mode="create", profile_names=profile_names)

            flash("Voucher created on the MikroTik router.", "success")
            return redirect(url_for("print_vouchers", voucher_id=voucher_id))

        voucher = {
            "username": f"user{secrets.randbelow(9000) + 1000}",
            "password": random_code(8),
            "profile": "default",
            "time_limit": "1h",
            "data_limit": "",
            "shared_users": "1",
            "expiry_date": "",
            "status": "unused",
            "comment": "",
        }
        if profile_names and voucher["profile"] not in profile_names:
            voucher["profile"] = profile_names[0]
        return render_template("voucher_form.html", voucher=voucher, mode="create", profile_names=profile_names)

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

        if request.method == "POST":
            data = voucher_from_form()
            error = validate_voucher(data)
            if error:
                flash(error, "danger")
                data["id"] = voucher_id
                return render_template("voucher_form.html", voucher=data, mode="edit", profile_names=profile_names)

            existing = get_voucher_by_username(data["username"], router["id"])
            if existing and existing["id"] != voucher_id:
                flash("Another local voucher on this router already uses this username.", "danger")
                data["id"] = voucher_id
                return render_template("voucher_form.html", voucher=data, mode="edit", profile_names=profile_names)

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
                return render_template("voucher_form.html", voucher=data, mode="edit", profile_names=profile_names)

            flash("Voucher updated on the MikroTik router.", "success")
            return redirect(url_for("vouchers"))

        return render_template("voucher_form.html", voucher=voucher, mode="edit", profile_names=profile_names)

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
            RouterClient(active_router_settings(router)).delete_voucher(voucher["routeros_id"], voucher["username"])
            mark_voucher_deleted(voucher_id, router["id"])
        except Exception as exc:
            flash(f"Could not delete voucher from MikroTik router: {exc}", "danger")
            return redirect(url_for("vouchers"))

        flash("Voucher deleted from the MikroTik router. Local history was kept.", "success")
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

        voucher = get_voucher(voucher_id, router["id"])
        if not voucher:
            flash("Voucher not found.", "warning")
            return redirect(url_for("vouchers"))

        data = voucher_to_dict(voucher)
        data["status"] = "unused"
        try:
            data["routeros_id"] = RouterClient(active_router_settings(router)).renew_voucher(data)
            renew_voucher_row(voucher_id, data, router["id"])
        except Exception as exc:
            flash(f"Could not renew voucher on MikroTik router: {exc}", "danger")
            return redirect(url_for("vouchers"))

        flash("Voucher renewed on the MikroTik router.", "success")
        return redirect(url_for("vouchers"))

    @app.route("/print")
    @app.route("/print/<int:voucher_id>")
    def print_vouchers(voucher_id: int | None = None):
        router = require_active_router()
        if not router:
            return redirect(url_for("routers_add"))

        vouchers_to_print = [get_voucher(voucher_id, router["id"])] if voucher_id else list_vouchers(router["id"])
        vouchers_to_print = [voucher for voucher in vouchers_to_print if voucher]
        return render_template("print.html", vouchers=vouchers_to_print)

    @app.route("/manifest.json")
    def manifest():
        return app.send_static_file("manifest.json")

    @app.route("/service-worker.js")
    def service_worker():
        return app.send_static_file("service-worker.js")

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


def is_production() -> bool:
    return os.environ.get("APP_ENV", "").strip().lower() in {"production", "prod"}


def env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def validate_startup_config() -> None:
    if not is_production():
        return

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

    required_mysql = ["MYSQL_HOST", "MYSQL_DATABASE", "MYSQL_USER", "MYSQL_PASSWORD"]
    for key in required_mysql:
        if not os.environ.get(key, "").strip():
            errors.append(f"Set {key}.")

    if os.environ.get("MYSQL_PASSWORD", "").strip() in {"change-this-password", "your_mysql_password"}:
        errors.append("Set MYSQL_PASSWORD to the real MySQL password.")

    if errors:
        raise RuntimeError("Production configuration error: " + " ".join(errors))


def configure_http_settings(app: Flask) -> None:
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
    app.config["SESSION_COOKIE_SECURE"] = env_flag("SESSION_COOKIE_SECURE", is_production())

    if env_flag("TRUST_PROXY", is_production()):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)


def router_session_active() -> bool:
    if not current_user_id():
        return False
    if trial_has_expired():
        clear_router_session()
        return False
    router_session = get_router_session()
    if not router_session:
        return False
    if get_router(int(router_session["router_id"])):
        return True
    clear_router_session()
    return False


def session_minutes_left() -> int:
    router_session = get_router_session()
    if not router_session:
        return 0
    seconds_left = max(0, int(float(router_session["expires_at"]) - time.time()))
    return max(1, (seconds_left + 59) // 60)


def start_router_session(router_id: int, router) -> None:
    clear_router_session()
    user_id = current_user_id()
    if not user_id:
        raise RuntimeError("Sign in to Karte before connecting a router.")

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
                row_value(router, "router_password"),
                expires_at,
                now,
                now,
            ),
        )
        db.commit()

    session.permanent = True
    session["router_id"] = int(router_id)
    session["router_session_token"] = token


def clear_router_session() -> None:
    token = session.get("router_session_token")
    if token:
        with closing(get_db()) as db:
            db.execute("DELETE FROM router_sessions WHERE token = ?", (token,))
            db.commit()

    for key in ["router_id", "router_session_token"]:
        session.pop(key, None)


def get_router_session() -> sqlite3.Row | None:
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


def safe_next_url(next_url: str | None) -> str | None:
    if next_url and next_url.startswith("/") and not next_url.startswith("//"):
        return next_url
    return None


def current_user_id() -> int | None:
    user_id = session.get("user_id")
    return int(user_id) if user_id else None


def current_user():
    user_id = current_user_id()
    return get_app_user(user_id) if user_id else None


def current_trial_status() -> dict[str, object] | None:
    user = current_user()
    if not user:
        return None
    return trial_status_for_user(user)


def trial_status_for_user(user) -> dict[str, object]:
    plan = row_value(user, "plan", "trial") or "trial"
    is_trial = plan == "trial"
    ends_at_text = row_value(user, "trial_ends_at")
    ends_at = parse_local_datetime(ends_at_text)
    expired = bool(is_trial and ends_at and ends_at <= datetime.now())
    seconds_left = max(0, int((ends_at - datetime.now()).total_seconds())) if ends_at else TRIAL_DAYS * 86400
    days_left = 0 if expired else max(1, (seconds_left + 86399) // 86400)
    router_limit = parse_positive_int(row_value(user, "router_limit"), TRIAL_ROUTER_LIMIT)
    user_id = int(row_value(user, "id", "0") or 0)

    return {
        "is_trial": is_trial,
        "plan": plan,
        "expired": expired,
        "days_left": days_left,
        "trial_ends_at": ends_at_text,
        "router_limit": router_limit,
        "router_count": router_count_for_user(user_id),
    }


def trial_has_expired() -> bool:
    status = current_trial_status()
    return bool(status and status["is_trial"] and status["expired"])


def trial_router_limit_error() -> str | None:
    status = current_trial_status()
    if not status or not status["is_trial"]:
        return None
    if status["expired"]:
        return "Your 30-day free trial has ended. Router management is disabled."
    if int(status["router_count"]) >= int(status["router_limit"]):
        limit = int(status["router_limit"])
        router_word = "router" if limit == 1 else "routers"
        return f"Free trial allows only {limit} {router_word} for {TRIAL_DAYS} days."
    return None


def upgrade_account_router_limit(user_id: int, router_limit: int) -> None:
    with closing(get_db()) as db:
        db.execute(
            """
            UPDATE app_users
            SET plan = 'paid', router_limit = ?, updated_at = ?
            WHERE id = ?
            """,
            (router_limit, timestamp(), int(user_id)),
        )
        db.commit()


def login_app_user(user) -> None:
    clear_router_session()
    session.permanent = True
    session["user_id"] = int(user["id"])


def validate_app_user(name: str, email: str, password: str) -> str | None:
    if not name or not email or not password:
        return "Please fill in your name, email, and password."
    if "@" not in email or "." not in email.rsplit("@", 1)[-1]:
        return "Enter a valid email address."
    if len(password) < 8:
        return "Use a password with at least 8 characters."
    return None


def app_user_count() -> int:
    with closing(get_db()) as db:
        return int(db.execute("SELECT COUNT(*) FROM app_users").fetchone()[0])


def get_app_user(user_id: int | None):
    if not user_id:
        return None
    with closing(get_db()) as db:
        return db.execute("SELECT * FROM app_users WHERE id = ?", (int(user_id),)).fetchone()


def find_app_user_by_email(email: str):
    with closing(get_db()) as db:
        return db.execute("SELECT * FROM app_users WHERE email = ?", (email,)).fetchone()


def create_app_user(name: str, email: str, password: str) -> int:
    if find_app_user_by_email(email):
        raise ValueError("That email is already registered.")

    is_first_user = app_user_count() == 0
    now = timestamp()
    trial_ends_at = format_timestamp(datetime.now() + timedelta(days=TRIAL_DAYS))
    with closing(get_db()) as db:
        cursor = db.execute(
            """
            INSERT INTO app_users (
                name, email, password_hash, is_admin, plan, trial_started_at, trial_ends_at,
                router_limit, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                email,
                generate_password_hash(password),
                1 if is_first_user else 0,
                "trial",
                now,
                trial_ends_at,
                TRIAL_ROUTER_LIMIT,
                now,
                now,
            ),
        )
        db.commit()
        return int(cursor.lastrowid)


def claim_unowned_routers(user_id: int) -> None:
    with closing(get_db()) as db:
        db.execute(
            "UPDATE routers SET owner_user_id = ? WHERE owner_user_id IS NULL",
            (int(user_id),),
        )
        db.commit()


def login_defaults() -> dict[str, str]:
    router = get_active_router() or first_router()
    if router:
        return router_to_form_data(router)

    return {
        "name": "Router",
        "router_ip": "",
        "api_port": "8728",
        "router_username": "",
        "router_password": "",
    }


def save_login_router(router: dict[str, str]) -> int:
    existing = find_router_by_login(router)
    if existing:
        update_router(existing["id"], router)
        return int(existing["id"])
    return insert_router(router)


def load_env_file() -> None:
    for path in [BASE_DIR / ".env", STORAGE_DIR / "config.env"]:
        if not path.exists():
            continue

        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


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


class MySqlDb:
    def __init__(self):
        if mysql_connector is None:
            raise RuntimeError("MySQL is selected but mysql-connector-python is not installed. Run: pip install -r requirements.txt")
        self.conn = mysql_connection()

    def execute(self, sql: str, params: tuple = ()):
        cursor = self.conn.cursor()
        cursor.execute(sql.replace("?", "%s"), params or ())
        return MySqlCursor(cursor)

    def commit(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


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


def mysql_connection():
    config = mysql_config()
    try:
        return mysql_connector.connect(**config)
    except mysql_connector.Error as exc:
        if getattr(exc, "errno", None) != 1049:
            raise

        database = str(config.pop("database"))
        with closing(mysql_connector.connect(**config)) as conn:
            cursor = conn.cursor()
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {mysql_identifier(database)} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
            conn.commit()

        config["database"] = database
        return mysql_connector.connect(**config)


def mysql_identifier(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_]+", name):
        raise RuntimeError("MYSQL_DATABASE may only contain letters, numbers, and underscores.")
    return f"`{name}`"


def get_db():
    if using_mysql():
        return MySqlDb()

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with closing(get_db()) as db:
        if using_mysql():
            init_mysql_db(db)
            db.commit()
            return

        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS settings (
                `key` TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS app_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                plan TEXT NOT NULL DEFAULT 'trial',
                trial_started_at TEXT NOT NULL DEFAULT '',
                trial_ends_at TEXT NOT NULL DEFAULT '',
                router_limit INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS routers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_user_id INTEGER,
                name TEXT NOT NULL,
                router_ip TEXT NOT NULL,
                api_port TEXT NOT NULL DEFAULT '8728',
                router_username TEXT NOT NULL,
                router_password TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vouchers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                router_id INTEGER,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                profile TEXT NOT NULL,
                time_limit TEXT NOT NULL,
                data_limit TEXT NOT NULL DEFAULT '',
                shared_users TEXT NOT NULL DEFAULT '1',
                status TEXT NOT NULL DEFAULT 'unused',
                `comment` TEXT NOT NULL DEFAULT '',
                expiry_date TEXT NOT NULL DEFAULT '',
                activated_at TEXT NOT NULL DEFAULT '',
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
            """
        )
        migrate_saas_schema(db)
        migrate_legacy_router(db)
        migrate_vouchers_schema(db)
        migrate_voucher_details_schema(db)
        db.execute("CREATE INDEX IF NOT EXISTS idx_vouchers_router_id ON vouchers(router_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_vouchers_status ON vouchers(status)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_routers_owner_user_id ON routers(owner_user_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_router_sessions_user_id ON router_sessions(user_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_router_sessions_expires_at ON router_sessions(expires_at)")
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
        CREATE TABLE IF NOT EXISTS app_users (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(191) NOT NULL,
            email VARCHAR(191) NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_admin TINYINT NOT NULL DEFAULT 0,
            plan VARCHAR(32) NOT NULL DEFAULT 'trial',
            trial_started_at VARCHAR(19) NOT NULL DEFAULT '',
            trial_ends_at VARCHAR(19) NOT NULL DEFAULT '',
            router_limit INT NOT NULL DEFAULT 1,
            created_at VARCHAR(19) NOT NULL,
            updated_at VARCHAR(19) NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS routers (
            id INT PRIMARY KEY AUTO_INCREMENT,
            owner_user_id INT NULL,
            name VARCHAR(191) NOT NULL,
            router_ip VARCHAR(191) NOT NULL,
            api_port VARCHAR(20) NOT NULL DEFAULT '8728',
            router_username VARCHAR(191) NOT NULL,
            router_password TEXT NOT NULL,
            created_at VARCHAR(19) NOT NULL,
            updated_at VARCHAR(19) NOT NULL,
            INDEX idx_routers_owner_user_id (owner_user_id),
            INDEX idx_routers_login (router_ip, api_port, router_username)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS vouchers (
            id INT PRIMARY KEY AUTO_INCREMENT,
            router_id INT NULL,
            username VARCHAR(191) NOT NULL,
            password TEXT NOT NULL,
            profile VARCHAR(191) NOT NULL,
            time_limit VARCHAR(64) NOT NULL,
            data_limit VARCHAR(64) NOT NULL DEFAULT '',
            shared_users VARCHAR(16) NOT NULL DEFAULT '1',
            status VARCHAR(32) NOT NULL DEFAULT 'unused',
            `comment` TEXT,
            expiry_date VARCHAR(32) NOT NULL DEFAULT '',
            activated_at VARCHAR(19) NOT NULL DEFAULT '',
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
            CONSTRAINT fk_vouchers_router
                FOREIGN KEY (router_id) REFERENCES routers(id)
                ON DELETE CASCADE
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
            CONSTRAINT fk_router_sessions_router
                FOREIGN KEY (router_id) REFERENCES routers(id)
                ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    migrate_mysql_saas_schema(db)
    migrate_mysql_voucher_details_schema(db)


def migrate_saas_schema(db: sqlite3.Connection) -> None:
    user_columns = table_columns(db, "app_users")
    user_new_columns = {
        "plan": "TEXT NOT NULL DEFAULT 'trial'",
        "trial_started_at": "TEXT NOT NULL DEFAULT ''",
        "trial_ends_at": "TEXT NOT NULL DEFAULT ''",
        "router_limit": f"INTEGER NOT NULL DEFAULT {TRIAL_ROUTER_LIMIT}",
    }
    for name, definition in user_new_columns.items():
        if name not in user_columns:
            db.execute(f"ALTER TABLE app_users ADD COLUMN `{name}` {definition}")
    backfill_trial_columns(db)

    router_columns = table_columns(db, "routers")
    if "owner_user_id" not in router_columns:
        db.execute("ALTER TABLE routers ADD COLUMN owner_user_id INTEGER")

    session_columns = table_columns(db, "router_sessions")
    if "user_id" not in session_columns:
        db.execute("ALTER TABLE router_sessions ADD COLUMN user_id INTEGER")


def migrate_mysql_saas_schema(db) -> None:
    user_columns = mysql_table_columns(db, "app_users")
    user_new_columns = {
        "plan": "VARCHAR(32) NOT NULL DEFAULT 'trial'",
        "trial_started_at": "VARCHAR(19) NOT NULL DEFAULT ''",
        "trial_ends_at": "VARCHAR(19) NOT NULL DEFAULT ''",
        "router_limit": f"INT NOT NULL DEFAULT {TRIAL_ROUTER_LIMIT}",
    }
    for name, definition in user_new_columns.items():
        if name not in user_columns:
            db.execute(f"ALTER TABLE app_users ADD COLUMN `{name}` {definition}")
    backfill_trial_columns(db)

    router_columns = mysql_table_columns(db, "routers")
    if "owner_user_id" not in router_columns:
        db.execute("ALTER TABLE routers ADD COLUMN owner_user_id INT NULL")
        db.execute("CREATE INDEX idx_routers_owner_user_id ON routers(owner_user_id)")

    session_columns = mysql_table_columns(db, "router_sessions")
    if "user_id" not in session_columns:
        db.execute("ALTER TABLE router_sessions ADD COLUMN user_id INT NULL")
        db.execute("CREATE INDEX idx_router_sessions_user_id ON router_sessions(user_id)")


def backfill_trial_columns(db) -> None:
    started_at = timestamp()
    ends_at = format_timestamp(datetime.now() + timedelta(days=TRIAL_DAYS))
    db.execute("UPDATE app_users SET plan = 'trial' WHERE plan IS NULL OR plan = ''")
    db.execute(
        "UPDATE app_users SET trial_started_at = ? WHERE trial_started_at IS NULL OR trial_started_at = ''",
        (started_at,),
    )
    db.execute(
        "UPDATE app_users SET trial_ends_at = ? WHERE trial_ends_at IS NULL OR trial_ends_at = ''",
        (ends_at,),
    )
    db.execute(
        "UPDATE app_users SET router_limit = ? WHERE router_limit IS NULL OR router_limit < 1",
        (TRIAL_ROUTER_LIMIT,),
    )


def migrate_voucher_details_schema(db: sqlite3.Connection) -> None:
    columns = table_columns(db, "vouchers")
    new_columns = {
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
            settings.get("router_password", ""),
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
    return defaults


def save_settings(settings: dict[str, str]) -> None:
    with closing(get_db()) as db:
        for key in ["router_ip", "api_port", "router_username", "router_password"]:
            if using_mysql():
                db.execute(
                    """
                    INSERT INTO settings (`key`, value)
                    VALUES (?, ?)
                    ON DUPLICATE KEY UPDATE value = VALUES(value)
                    """,
                    (key, settings.get(key, "")),
                )
            else:
                db.execute(
                    """
                    INSERT INTO settings (`key`, value)
                    VALUES (?, ?)
                    ON CONFLICT(`key`) DO UPDATE SET value = excluded.value
                    """,
                    (key, settings.get(key, "")),
                )
        db.commit()


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
        "data_limit",
        "shared_users",
        "status",
        "comment",
        "expiry_date",
        "routeros_id",
    ]
    return {field: row_value(voucher, field) for field in fields}


def router_to_settings(router) -> dict[str, str]:
    return {
        "router_ip": row_value(router, "router_ip"),
        "api_port": row_value(router, "api_port", "8728"),
        "router_username": row_value(router, "router_username"),
        "router_password": row_value(router, "router_password"),
    }


def router_to_form_data(router) -> dict[str, str]:
    return {
        "name": row_value(router, "name", "Router"),
        **router_to_settings(router),
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
    return {
        "name": request.form.get("name", default_name).strip() or default_name,
        "router_ip": request.form.get("router_ip", row_value(fallback, "router_ip")).strip(),
        "api_port": request.form.get("api_port", row_value(fallback, "api_port", "8728")).strip() or "8728",
        "router_username": request.form.get("router_username", row_value(fallback, "router_username")).strip(),
        "router_password": request.form.get("router_password", row_value(fallback, "router_password")),
    }


def list_routers() -> list[sqlite3.Row]:
    user_id = current_user_id()
    if not user_id:
        return []
    with closing(get_db()) as db:
        return db.execute(
            "SELECT * FROM routers WHERE owner_user_id = ? ORDER BY name, id",
            (user_id,),
        ).fetchall()


def router_count_for_user(user_id: int) -> int:
    if not user_id:
        return 0
    with closing(get_db()) as db:
        return int(
            db.execute(
                "SELECT COUNT(*) FROM routers WHERE owner_user_id = ?",
                (int(user_id),),
            ).fetchone()[0]
        )


def get_router(router_id: int) -> sqlite3.Row | None:
    user_id = current_user_id()
    if not user_id:
        return None
    with closing(get_db()) as db:
        return db.execute(
            "SELECT * FROM routers WHERE id = ? AND owner_user_id = ?",
            (router_id, user_id),
        ).fetchone()


def find_router_by_login(router: dict[str, str]) -> sqlite3.Row | None:
    user_id = current_user_id()
    if not user_id:
        return None
    with closing(get_db()) as db:
        return db.execute(
            """
            SELECT * FROM routers
            WHERE owner_user_id = ? AND router_ip = ? AND api_port = ? AND router_username = ?
            ORDER BY id LIMIT 1
            """,
            (user_id, router["router_ip"], router["api_port"], router["router_username"]),
        ).fetchone()


def first_router() -> sqlite3.Row | None:
    user_id = current_user_id()
    if not user_id:
        return None
    with closing(get_db()) as db:
        return db.execute(
            "SELECT * FROM routers WHERE owner_user_id = ? ORDER BY id LIMIT 1",
            (user_id,),
        ).fetchone()


def get_active_router() -> sqlite3.Row | None:
    router_session = get_router_session()
    if router_session:
        router = get_router(int(router_session["router_id"]))
        if router:
            session["router_id"] = int(router["id"])
            return router
        clear_router_session()

    return None


def set_active_router(router_id: int) -> None:
    session["router_id"] = int(router_id)


def require_active_router() -> sqlite3.Row | None:
    router = get_active_router()
    if not router:
        flash("Add or login to a router first.", "warning")
    return router


def insert_router(router: dict[str, str]) -> int:
    user_id = current_user_id()
    if not user_id:
        raise RuntimeError("Sign in to Karte before saving routers.")

    limit_error = trial_router_limit_error()
    if limit_error:
        raise ValueError(limit_error)

    now = timestamp()
    with closing(get_db()) as db:
        cursor = db.execute(
            """
            INSERT INTO routers (owner_user_id, name, router_ip, api_port, router_username, router_password, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                router["name"],
                router["router_ip"],
                router["api_port"],
                router["router_username"],
                router["router_password"],
                now,
                now,
            ),
        )
        db.commit()
        return int(cursor.lastrowid)


def update_router(router_id: int, router: dict[str, str]) -> None:
    user_id = current_user_id()
    if not user_id:
        raise RuntimeError("Sign in to Karte before updating routers.")

    with closing(get_db()) as db:
        db.execute(
            """
            UPDATE routers
            SET name = ?, router_ip = ?, api_port = ?, router_username = ?, router_password = ?, updated_at = ?
            WHERE id = ? AND owner_user_id = ?
            """,
            (
                router["name"],
                router["router_ip"],
                router["api_port"],
                router["router_username"],
                router["router_password"],
                timestamp(),
                router_id,
                user_id,
            ),
        )
        db.commit()


def delete_router(router_id: int) -> None:
    user_id = current_user_id()
    if not user_id:
        return

    with closing(get_db()) as db:
        router = db.execute(
            "SELECT id FROM routers WHERE id = ? AND owner_user_id = ?",
            (router_id, user_id),
        ).fetchone()
        if not router:
            return
        db.execute("DELETE FROM vouchers WHERE router_id = ?", (router_id,))
        db.execute("DELETE FROM routers WHERE id = ? AND owner_user_id = ?", (router_id, user_id))
        db.commit()


VOUCHER_STATUSES = ["unused", "activated", "online", "used", "expired", "deleted", "disabled"]


def list_vouchers(router_id: int, status: str = "all") -> list[sqlite3.Row]:
    with closing(get_db()) as db:
        if status in VOUCHER_STATUSES:
            return db.execute(
                "SELECT * FROM vouchers WHERE router_id = ? AND status = ? ORDER BY created_at DESC, id DESC",
                (router_id, status),
            ).fetchall()
        return db.execute(
            "SELECT * FROM vouchers WHERE router_id = ? ORDER BY created_at DESC, id DESC",
            (router_id,),
        ).fetchall()


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


def count_vouchers(router_id: int | None = None) -> int:
    with closing(get_db()) as db:
        if router_id is None:
            return int(db.execute("SELECT COUNT(*) FROM vouchers").fetchone()[0])
        return int(db.execute("SELECT COUNT(*) FROM vouchers WHERE router_id = ?", (router_id,)).fetchone()[0])


def voucher_status_counts(router_id: int) -> dict[str, int]:
    counts = {status: 0 for status in VOUCHER_STATUSES}
    with closing(get_db()) as db:
        rows = db.execute(
            "SELECT status, COUNT(*) AS total FROM vouchers WHERE router_id = ? GROUP BY status",
            (router_id,),
        ).fetchall()
    for row in rows:
        counts[row["status"] or "unused"] = int(row["total"])
    counts["all"] = sum(counts.values())
    return counts


def insert_voucher(voucher: dict[str, str], router_id: int) -> int:
    now = timestamp()
    with closing(get_db()) as db:
        cursor = db.execute(
            """
            INSERT INTO vouchers (
                router_id, username, password, profile, time_limit, data_limit, shared_users,
                status, `comment`, expiry_date, routeros_id, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                router_id,
                voucher["username"],
                voucher["password"],
                voucher["profile"],
                voucher["time_limit"],
                voucher.get("data_limit", ""),
                voucher.get("shared_users", "1"),
                voucher.get("status", "unused"),
                voucher.get("comment", ""),
                voucher.get("expiry_date", ""),
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
            SET username = ?, password = ?, profile = ?, time_limit = ?, data_limit = ?, shared_users = ?,
                status = ?, `comment` = ?, expiry_date = ?, routeros_id = ?, updated_at = ?
            WHERE id = ? AND router_id = ?
            """,
            (
                voucher["username"],
                voucher["password"],
                voucher["profile"],
                voucher["time_limit"],
                voucher.get("data_limit", ""),
                voucher.get("shared_users", "1"),
                voucher.get("status", "unused"),
                voucher.get("comment", ""),
                voucher.get("expiry_date", ""),
                voucher.get("routeros_id", ""),
                timestamp(),
                voucher_id,
                router_id,
            ),
        )
        db.commit()


def mark_voucher_deleted(voucher_id: int, router_id: int) -> None:
    with closing(get_db()) as db:
        db.execute(
            """
            UPDATE vouchers
            SET status = 'deleted', routeros_id = '', online_users = 0, updated_at = ?
            WHERE id = ? AND router_id = ?
            """,
            (timestamp(), voucher_id, router_id),
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
            SET routeros_id = ?, status = 'unused', activated_at = '', first_login_mac = '',
                first_login_ip = '', device_name = '', uptime_used = '', data_used = '',
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
            WHERE router_id = ? AND status <> 'deleted'
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


def sync_all_routers() -> dict[str, int]:
    summary = {"routers": 0, "checked": 0, "online": 0, "expired": 0}
    for router in list_routers_for_sync():
        try:
            result = sync_router_vouchers(router)
        except Exception:
            continue

        summary["routers"] += 1
        for key in ["checked", "online", "expired"]:
            summary[key] += result[key]
    return summary


def sync_router_vouchers(router, settings: dict[str, str] | None = None) -> dict[str, int]:
    router_id = int(row_value(router, "id", "0"))
    client = RouterClient(settings or router_to_settings(router))
    remote_users = client.list_hotspot_users()
    active_users = client.list_active_hotspot_users()
    remote_by_id = {routeros_item_id(user): user for user in remote_users if routeros_item_id(user)}
    remote_by_name = {str(user.get("name", "")): user for user in remote_users if user.get("name")}
    active_by_name: dict[str, list[dict]] = {}

    for active in active_users:
        username = str(active.get("user") or active.get("name") or "").strip()
        if username:
            active_by_name.setdefault(username, []).append(active)

    summary = {"checked": 0, "online": 0, "expired": 0}
    for voucher in list_vouchers_for_sync(router_id):
        summary["checked"] += 1
        username = row_value(voucher, "username")
        remote = remote_by_id.get(row_value(voucher, "routeros_id")) or remote_by_name.get(username)
        active_rows = active_by_name.get(username, [])

        if not remote:
            if row_value(voucher, "status", "unused") not in ["deleted", "expired"]:
                update_voucher_sync_fields(
                    int(row_value(voucher, "id", "0")),
                    router_id,
                    {"status": "deleted", "routeros_id": "", "online_users": 0},
                )
            continue

        remote_id = routeros_item_id(remote)
        uptime_used = routeros_uptime_used(remote, active_rows)
        data_used = routeros_data_used(remote, active_rows)
        status = next_voucher_status(voucher, remote, active_rows)
        fields: dict[str, object] = {
            "routeros_id": remote_id,
            "status": status,
            "online_users": len(active_rows),
            "uptime_used": uptime_used,
            "data_used": str(data_used) if data_used is not None else row_value(voucher, "data_used"),
        }

        if active_rows:
            summary["online"] += 1
            first_active = active_rows[0]
            fields["activated_at"] = row_value(voucher, "activated_at") or timestamp()
            fields["first_login_mac"] = row_value(voucher, "first_login_mac") or str(first_active.get("mac-address", ""))
            fields["first_login_ip"] = row_value(voucher, "first_login_ip") or str(first_active.get("address") or first_active.get("ip") or "")
            fields["device_name"] = row_value(voucher, "device_name") or str(first_active.get("host-name") or first_active.get("host") or "")

        if voucher_should_expire(voucher, uptime_used, data_used):
            client.remove_active_hotspot_sessions(username)
            client.delete_voucher(remote_id, username)
            fields.update({"status": "expired", "routeros_id": "", "online_users": 0})
            summary["expired"] += 1

        update_voucher_sync_fields(int(row_value(voucher, "id", "0")), router_id, fields)

    return summary


def next_voucher_status(voucher, remote: dict, active_rows: list[dict]) -> str:
    current_status = row_value(voucher, "status", "unused")
    if current_status in ["expired", "deleted"]:
        return current_status
    if routeros_disabled(remote) or current_status == "disabled":
        return "disabled"
    if active_rows:
        return "online"
    if row_value(voucher, "activated_at"):
        return "activated"
    return "unused"


def voucher_should_expire(voucher, uptime_used: str, data_used: int | None) -> bool:
    if row_value(voucher, "status") in ["deleted", "disabled"]:
        return False

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


def start_background_sync(app: Flask) -> None:
    global SYNC_THREAD_STARTED
    if SYNC_THREAD_STARTED:
        return
    if os.environ.get("ENABLE_BACKGROUND_SYNC", "1").strip().lower() in ["0", "false", "no", "off"]:
        return

    SYNC_THREAD_STARTED = True
    thread = threading.Thread(target=background_sync_loop, args=(app,), daemon=True)
    thread.start()


def background_sync_loop(app: Flask) -> None:
    interval = sync_interval_seconds()
    time.sleep(min(15, interval))
    while True:
        try:
            with app.app_context():
                sync_all_routers()
        except Exception:
            pass
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
        "username": request.form.get("username", "").strip(),
        "password": request.form.get("password", "").strip(),
        "profile": request.form.get("profile", "").strip(),
        "time_limit": request.form.get("time_limit", "").strip(),
        "data_limit": request.form.get("data_limit", "").strip(),
        "shared_users": request.form.get("shared_users", "1").strip() or "1",
        "expiry_date": request.form.get("expiry_date", "").strip(),
        "status": request.form.get("status", "unused").strip() or "unused",
        "comment": request.form.get("comment", "").strip(),
    }


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
    if voucher.get("shared_users") and not voucher["shared_users"].isdigit():
        return "Users allowed must be a number."
    if voucher.get("status") not in VOUCHER_STATUSES:
        return "Choose a valid voucher status."
    return None


def validate_router(router: dict[str, str]) -> str | None:
    if not router["name"] or not router["router_ip"] or not router["api_port"] or not router["router_username"]:
        return "Please fill in the router name, IP address, API port, and MikroTik username."
    if not router["api_port"].isdigit():
        return "The API port must be a number."
    return None


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


def random_code(length: int = 8) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


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


def parse_positive_int(value, default: int) -> int:
    try:
        parsed = int(str(value or "").strip())
    except ValueError:
        return default
    return parsed if parsed > 0 else default


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
    for item in [*active_rows, remote]:
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
        "connection_mode": "wireguard",
        "wan_interface": "ether1",
        "bridge_name": "hotspot-bridge",
        "gateway_ip": "10.5.50.1",
        "lan_address": "10.5.50.1/24",
        "lan_network": "10.5.50.0/24",
        "pool_range": "10.5.50.10-10.5.50.254",
        "dns_name": "login.hotspot",
        "api_port": settings.get("api_port") or "8728",
        "api_user": settings.get("router_username") or "voucher-api",
        "api_password": settings.get("router_password") or "CHANGE-ME-STRONG-PASSWORD",
        "limit_api_to_wireguard": "yes",
        "wg_interface": "voucher-wg",
        "wg_router_address": "10.10.10.2/32",
        "wg_listen_port": "13231",
        "wg_mtu": "1420",
        "wg_server_public_key": "PASTE_VPS_WIREGUARD_PUBLIC_KEY",
        "wg_server_endpoint_address": "your-vps-public-ip",
        "wg_server_endpoint_port": "51820",
        "wg_server_allowed_address": "10.10.10.1/32",
        "wg_persistent_keepalive": "25s",
    }

    if request.method != "POST":
        return defaults

    return {
        key: request.form.get(key, value).strip() or value
        for key, value in defaults.items()
    }


def routeros_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_router_setup_script(options: dict[str, str]) -> str:
    values = {key: routeros_quote(value) for key, value in options.items()}
    use_wireguard = options.get("connection_mode") == "wireguard"
    wireguard_section = build_wireguard_setup_section(options, values) if use_wireguard else ':put "WireGuard skipped. App is expected to reach this router on the local network."'
    api_limit_section = build_api_limit_section(options)
    done_message = (
        f'Add this router in the VPS app using WireGuard IP {strip_cidr(options["wg_router_address"])}, '
        f'API user {options["api_user"]}, and the API password from this page.'
        if use_wireguard
        else "Add this router in the app using its LAN IP address and API login."
    )

    return f""":put "Karte RouterOS Management System setup started"

# Assumption:
# - {options['wan_interface']} is the internet/WAN port.
# - Every other Ethernet port plus wireless/wifi interfaces will become hotspot.
# Change the WAN port on the app page before copying if your internet cable uses another port.

:local wan {values['wan_interface']}
:local bridge {values['bridge_name']}
:local gatewayIp {values['gateway_ip']}
:local lanAddress {values['lan_address']}
:local lanNetwork {values['lan_network']}
:local poolRange {values['pool_range']}
:local dnsName {values['dns_name']}
:local apiPort {values['api_port']}
:local apiUser {values['api_user']}
:local apiPassword {values['api_password']}
:local apiGroup "voucher-api"
:local apiService "api"
:local hotspotPool "hotspot-pool"
:local dhcpName "hotspot-dhcp"
:local hotspotName "voucher-hotspot"
:local profileName "voucher-profile"

:local wgInterface {values['wg_interface']}
:local wgRouterAddress {values['wg_router_address']}
:local wgListenPort {values['wg_listen_port']}
:local wgMtu {values['wg_mtu']}
:local wgServerPublicKey {values['wg_server_public_key']}
:local wgServerEndpointAddress {values['wg_server_endpoint_address']}
:local wgServerEndpointPort {values['wg_server_endpoint_port']}
:local wgServerAllowedAddress {values['wg_server_allowed_address']}
:local wgPersistentKeepalive {values['wg_persistent_keepalive']}

:put "Creating hotspot bridge"
:if ([:len [/interface bridge find name=$bridge]] = 0) do={{
    /interface bridge add name=$bridge comment="Hotspot bridge for Karte RouterOS Management System"
}}

:put "Adding Ethernet ports to hotspot bridge, except WAN"
:foreach i in=[/interface ethernet find] do={{
    :local ifName [/interface ethernet get $i name]
    :if ($ifName != $wan) do={{
        :if ([:len [/interface bridge port find interface=$ifName]] = 0) do={{
            /interface bridge port add bridge=$bridge interface=$ifName
        }}
    }}
}}

:put "Adding legacy wireless interfaces to hotspot bridge"
:do {{
    :foreach i in=[/interface wireless find] do={{
        :local ifName [/interface wireless get $i name]
        /interface wireless set $i disabled=no mode=ap-bridge
        :if ([:len [/interface bridge port find interface=$ifName]] = 0) do={{
            /interface bridge port add bridge=$bridge interface=$ifName
        }}
    }}
}} on-error={{ :put "No legacy wireless interfaces found" }}

:put "Adding WiFiWave2/wifi interfaces to hotspot bridge"
:do {{
    :foreach i in=[/interface wifi find] do={{
        :local ifName [/interface wifi get $i name]
        /interface wifi set $i disabled=no
        :if ([:len [/interface bridge port find interface=$ifName]] = 0) do={{
            /interface bridge port add bridge=$bridge interface=$ifName
        }}
    }}
}} on-error={{ :put "No wifi interfaces found" }}

:put "Setting hotspot bridge IP address"
:if ([:len [/ip address find interface=$bridge address=$lanAddress]] = 0) do={{
    /ip address add address=$lanAddress interface=$bridge comment="Hotspot LAN gateway"
}}

:put "Creating DHCP pool"
:if ([:len [/ip pool find name=$hotspotPool]] = 0) do={{
    /ip pool add name=$hotspotPool ranges=$poolRange
}} else={{
    /ip pool set [find name=$hotspotPool] ranges=$poolRange
}}

:put "Creating DHCP server"
:if ([:len [/ip dhcp-server find name=$dhcpName]] = 0) do={{
    /ip dhcp-server add name=$dhcpName interface=$bridge address-pool=$hotspotPool disabled=no
}} else={{
    /ip dhcp-server set [find name=$dhcpName] interface=$bridge address-pool=$hotspotPool disabled=no
}}

:if ([:len [/ip dhcp-server network find address=$lanNetwork]] = 0) do={{
    /ip dhcp-server network add address=$lanNetwork gateway=$gatewayIp dns-server=$gatewayIp comment="Hotspot voucher network"
}}

:put "Enabling DNS for hotspot clients"
/ip dns set allow-remote-requests=yes

:put "Making WAN receive internet by DHCP if no DHCP client exists"
:if ([:len [/ip dhcp-client find interface=$wan]] = 0) do={{
    /ip dhcp-client add interface=$wan disabled=no use-peer-dns=yes use-peer-ntp=yes
}} else={{
    /ip dhcp-client enable [find interface=$wan]
}}

:put "Adding internet masquerade rule"
:if ([:len [/ip firewall nat find chain=srcnat out-interface=$wan action=masquerade]] = 0) do={{
    /ip firewall nat add chain=srcnat out-interface=$wan action=masquerade comment="Hotspot voucher internet masquerade"
}}

:put "Creating hotspot profile"
:if ([:len [/ip hotspot profile find name=$profileName]] = 0) do={{
    /ip hotspot profile add name=$profileName hotspot-address=$gatewayIp dns-name=$dnsName html-directory=hotspot
}} else={{
    /ip hotspot profile set [find name=$profileName] hotspot-address=$gatewayIp dns-name=$dnsName html-directory=hotspot
}}

:put "Creating hotspot server"
:if ([:len [/ip hotspot find name=$hotspotName]] = 0) do={{
    /ip hotspot add name=$hotspotName interface=$bridge address-pool=$hotspotPool profile=$profileName disabled=no
}} else={{
    /ip hotspot set [find name=$hotspotName] interface=$bridge address-pool=$hotspotPool profile=$profileName disabled=no
}}

:put "Configuring WireGuard for VPS-hosted app"
{wireguard_section}

:put "Enabling RouterOS API for Karte RouterOS Management System"
/ip service set [find name=$apiService] disabled=no port=[:tonum $apiPort]
{api_limit_section}

:put "Creating API user for Karte RouterOS Management System"
:if ([:len [/user group find name=$apiGroup]] = 0) do={{
    /user group add name=$apiGroup policy=read,write,api,test
}}
:if ([:len [/user find name=$apiUser]] = 0) do={{
    /user add name=$apiUser password=$apiPassword group=$apiGroup comment="Karte RouterOS Management System API user"
}} else={{
    /user set [find name=$apiUser] password=$apiPassword group=$apiGroup disabled=no
}}

:put "Karte RouterOS Management System setup finished"
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
    if options.get("connection_mode") == "wireguard" and options.get("limit_api_to_wireguard") == "yes":
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

        self.resource("/ip/hotspot/user/profile").add(**params)

    def create_voucher(self, voucher: dict[str, str]) -> str:
        user_resource = self.resource("/ip/hotspot/user")
        user_resource.add(**self.voucher_params(voucher))
        return self.find_remote_id(voucher["username"]) or ""

    def update_voucher(self, routeros_id: str | None, old_username: str, voucher: dict[str, str]) -> str:
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

        pool = routeros_api.RouterOsApiPool(
            self.settings["router_ip"],
            username=self.settings["router_username"],
            password=self.settings.get("router_password", ""),
            port=int(self.settings["api_port"]),
            plaintext_login=True,
        )
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
