import os
import re
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch


TEST_DIRECTORY = tempfile.TemporaryDirectory(dir=os.environ.get("KARTE_TEST_TMP") or None)
os.environ["APP_ENV"] = "testing"
os.environ["DB_ENGINE"] = "sqlite"
os.environ["SQLITE_DATABASE_PATH"] = os.path.join(TEST_DIRECTORY.name, "karte.sqlite")
os.environ["ENABLE_BACKGROUND_SYNC"] = "0"
os.environ["SECRET_KEY"] = "test-secret-key-that-is-long-enough-for-karte"
os.environ["ROUTER_ALLOWED_NETWORKS"] = "10.0.0.0/8,192.168.0.0/16"
os.environ["ROUTER_ALLOWED_PORTS"] = "8728,8729"

import app as karte


class FakeRouterClient:
    def __init__(self, users=None, active_users=None, delete_error=None, sticky_delete=False):
        self.users = [dict(user) for user in (users or [])]
        self.active_users = [dict(user) for user in (active_users or [])]
        self.delete_error = delete_error
        self.sticky_delete = sticky_delete
        self.tested = False

    def test_connection(self):
        self.tested = True
        return []

    def close(self):
        return None

    def list_hotspot_users(self):
        return [dict(user) for user in self.users]

    def list_active_hotspot_users(self):
        return [dict(user) for user in self.active_users]

    def remove_active_hotspot_sessions(self, username):
        self.active_users = [
            active
            for active in self.active_users
            if str(active.get("user") or active.get("name") or "") != username
        ]

    def delete_voucher(self, routeros_id, username):
        if self.delete_error:
            raise self.delete_error
        if self.sticky_delete:
            return
        self.users = [
            user
            for user in self.users
            if karte.routeros_item_id(user) != routeros_id and str(user.get("name", "")) != username
        ]

    def create_voucher(self, voucher):
        routeros_id = f"*{len(self.users) + 1}"
        self.users.append({"id": routeros_id, "name": voucher["username"], "disabled": "false"})
        return routeros_id

    def disable_voucher(self, routeros_id, username):
        for user in self.users:
            if karte.routeros_item_id(user) == routeros_id or user.get("name") == username:
                user["disabled"] = "true"

    def enable_voucher(self, routeros_id, username):
        for user in self.users:
            if karte.routeros_item_id(user) == routeros_id or user.get("name") == username:
                user["disabled"] = "false"

    def bind_voucher_to_mac(self, routeros_id, username, mac_address):
        return None


class ProductionHardeningTests(unittest.TestCase):
    def setUp(self):
        karte.app.config.update(TESTING=True)
        with closing(karte.get_db()) as db:
            for table in [
                "router_login_attempts",
                "router_sessions",
                "sales",
                "audit_logs",
                "reconciliation_issues",
                "vouchers",
                "voucher_batches",
                "packages",
                "wireguard_interfaces",
                "routers",
                "users",
            ]:
                db.execute(f"DELETE FROM {table}")
            db.commit()
        karte.insert_user(
            {
                "username": "test-admin",
                "password": "test-password-123",
                "role": "admin",
                "active": "1",
            }
        )
        self.client = karte.app.test_client()

    def csrf_token(self, path="/login"):
        response = self.client.get(path)
        match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(match)
        return match.group(1).decode("ascii")

    def router(self, password="router-secret"):
        return karte.insert_router(
            {
                "name": "Test Router",
                "router_ip": "192.168.88.1",
                "api_port": "8728",
                "router_username": "admin",
                "router_password": password,
            }
        )

    def login(self):
        self.app_login()
        token = self.csrf_token()
        with (
            patch.object(karte.RouterClient, "test_connection", return_value=[]),
            patch.object(
                karte,
                "test_and_reconcile_router",
                return_value={"checked": 0, "online": 0, "expired": 0, "unrecognized": 0},
            ),
        ):
            response = self.client.post(
                "/login",
                data={
                    "csrf_token": token,
                    "name": "Test Router",
                    "router_ip": "192.168.88.1",
                    "api_port": "8728",
                    "router_username": "admin",
                    "router_password": "router-secret",
                },
            )
        self.assertEqual(response.status_code, 302)

    def app_login(self, username="test-admin", password="test-password-123"):
        token = self.csrf_token("/account/login")
        response = self.client.post(
            "/account/login",
            data={
                "csrf_token": token,
                "username": username,
                "password": password,
            },
        )
        self.assertEqual(response.status_code, 302)
        return response

    def test_router_and_wireguard_pages_require_router_login(self):
        for path in ["/routers", "/wireguard", "/vouchers"]:
            response = self.client.get(path)
            self.assertEqual(response.status_code, 302)
            self.assertIn("/login", response.headers["Location"])

    def test_login_page_never_renders_saved_router_password(self):
        router_id = self.router(password="never-render-this-secret")
        self.app_login()
        response = self.client.get(f"/login?router_id={router_id}")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"never-render-this-secret", response.data)
        self.assertIn(b'id="router_ip" name="router_ip" value=""', response.data)

    def test_csrf_is_required_and_valid_login_opens_router_pages(self):
        response = self.client.post("/login", data={"router_ip": "192.168.88.1"})
        self.assertEqual(response.status_code, 400)
        self.login()
        self.assertEqual(self.client.get("/routers").status_code, 200)

    def test_router_session_cannot_open_another_saved_router(self):
        self.login()
        other_router_id = karte.insert_router(
            {
                "name": "Other Router",
                "router_ip": "10.10.10.2",
                "api_port": "8728",
                "router_username": "other-admin",
                "router_password": "other-secret",
            }
        )
        response = self.client.get("/routers")
        self.assertNotIn(b"Other Router", response.data)
        response = self.client.get(f"/routers/{other_router_id}/edit")
        self.assertEqual(response.status_code, 302)

    def test_router_targets_are_limited_to_private_ip_and_api_ports(self):
        self.assertIsNone(karte.validate_router_target("10.10.10.2", "8728"))
        self.assertIn("outside", karte.validate_router_target("8.8.8.8", "8728"))
        self.assertIn("not allowed", karte.validate_router_target("192.168.88.1", "80"))
        self.assertIn("not a hostname", karte.validate_router_target("router.example.com", "8728"))

    def test_cashier_can_manage_vouchers_but_not_router_settings(self):
        self.router()
        karte.insert_user(
            {
                "username": "counter-one",
                "password": "counter-password-123",
                "role": "cashier",
                "active": "1",
            }
        )
        self.app_login("counter-one", "counter-password-123")

        self.assertEqual(self.client.get("/vouchers").status_code, 200)
        self.assertEqual(self.client.get("/packages").status_code, 200)
        for path in ["/settings", "/routers", "/wireguard", "/reconciliation/issues", "/account/users"]:
            response = self.client.get(path)
            self.assertEqual(response.status_code, 302)
            self.assertIn("/vouchers", response.headers["Location"])

    def test_packages_table_shows_live_voucher_stock(self):
        self.login()
        router = karte.find_router_by_login(
            {
                "router_ip": "192.168.88.1",
                "api_port": "8728",
                "router_username": "admin",
            }
        )
        package_id = karte.insert_package(
            {
                "name": "Day-5M",
                "rate_limit": "5M/2M",
                "validity_period": "1d",
                "data_cap": "",
                "price": "2.00",
                "archived": "0",
            },
            int(router["id"]),
        )
        for username, status in [("KT-UNUSED", "unused"), ("KT-ACTIVE", "active"), ("KT-EXPIRED", "expired")]:
            karte.insert_voucher(
                {
                    "package_id": str(package_id),
                    "username": username,
                    "password": "secret",
                    "profile": "Day-5M",
                    "time_limit": "1d",
                    "price": "2.00",
                    "status": status,
                },
                int(router["id"]),
            )
        response = self.client.get("/packages")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b">Unused</th>", response.data)
        self.assertIn(b">Active</th>", response.data)
        self.assertIn(b">Retired</th>", response.data)
        self.assertIn(b'data-label="Unused" class="text-center package-stock-number package-stock-unused">1</td>', response.data)
        self.assertIn(b'data-label="Active" class="text-center package-stock-number package-stock-active">1</td>', response.data)
        self.assertIn(b'data-label="Retired" class="text-center package-stock-number">1</td>', response.data)

    def test_database_prevents_duplicate_voucher_codes_and_sales(self):
        router_id = self.router()
        voucher = {
            "username": "KT-UNIQUE",
            "password": "secret",
            "profile": "one-day",
            "time_limit": "1d",
            "price": "1.00",
        }
        voucher_id = karte.insert_voucher(voucher, router_id)
        with self.assertRaises(sqlite3.IntegrityError):
            karte.insert_voucher(voucher, router_id)
        karte.record_sale(voucher_id, router_id, "1.00")
        with self.assertRaises(ValueError):
            karte.record_sale(voucher_id, router_id, "1.00")

    def test_any_usage_evidence_permanently_retires_unused_code(self):
        voucher = {"status": "unused", "uptime_used": "", "data_used": ""}
        self.assertFalse(karte.voucher_has_usage_evidence(voucher))
        self.assertTrue(karte.voucher_has_usage_evidence(voucher, "2s", 0))
        self.assertTrue(karte.voucher_has_usage_evidence(voucher, "", 1))
        self.assertTrue(karte.voucher_has_usage_evidence({**voucher, "activated_at": "2026-01-01 00:00:00"}))

    def test_bulk_validation_allows_more_than_one_thousand_codes(self):
        form = karte.default_voucher_batch()
        form.update({"package_id": "1", "quantity": "1001"})
        self.assertIsNone(karte.validate_voucher_batch(form, [{"id": 1}]))
        alphabet = karte.voucher_code_alphabet("uppercase_numbers", avoid_ambiguous=True)
        for character in "0O1IL":
            self.assertNotIn(character, alphabet)

    def test_legacy_router_password_is_migrated_to_encrypted_storage(self):
        router_id = self.router()
        with closing(karte.get_db()) as db:
            db.execute(
                "UPDATE routers SET router_password = ? WHERE id = ?",
                ("legacy-plaintext", router_id),
            )
            karte.migrate_legacy_secret_storage(db)
            db.commit()
            stored = db.execute(
                "SELECT router_password FROM routers WHERE id = ?",
                (router_id,),
            ).fetchone()["router_password"]
        self.assertTrue(stored.startswith("enc:"))
        self.assertEqual(karte.decrypt_secret(stored), "legacy-plaintext")

    def test_failed_expiry_deletion_keeps_status_and_retries(self):
        router_id = self.router()
        voucher_id = karte.insert_voucher(
            {
                "username": "KT-RETRY",
                "password": "secret",
                "profile": "one-hour",
                "time_limit": "1h",
                "status": "active",
                "activated_at": "1999-12-31 23:00:00",
                "expires_at": "2000-01-01 00:00:00",
                "first_login_mac": "AA:BB:CC:DD:EE:FF",
                "routeros_id": "*1",
            },
            router_id,
        )
        karte.update_voucher_sync_fields(
            voucher_id,
            router_id,
            {
                "activated_at": "1999-12-31 23:00:00",
                "first_login_mac": "AA:BB:CC:DD:EE:FF",
                "expires_at": "2000-01-01 00:00:00",
            },
        )
        router = karte.get_router(router_id)
        client = FakeRouterClient(
            users=[{"id": "*1", "name": "KT-RETRY", "disabled": "false"}],
            delete_error=RuntimeError("simulated RouterOS delete failure"),
        )

        result = karte.sync_router_vouchers_with_client(router, client)

        self.assertEqual(result["expired"], 0)
        voucher = karte.get_voucher(voucher_id, router_id)
        self.assertEqual(voucher["status"], "active")
        self.assertEqual(voucher["routeros_id"], "*1")
        self.assertEqual(voucher["retry_count"], 1)
        self.assertIn("simulated RouterOS delete failure", voucher["last_error"])
        with closing(karte.get_db()) as db:
            expiry_audits = db.execute(
                "SELECT COUNT(*) FROM audit_logs WHERE entity_id = ? AND action = 'expire'",
                (voucher_id,),
            ).fetchone()[0]
        self.assertEqual(expiry_audits, 0)

    def test_unconfirmed_expiry_deletion_is_retried(self):
        router_id = self.router()
        voucher_id = karte.insert_voucher(
            {
                "username": "KT-STILL-THERE",
                "password": "secret",
                "profile": "one-hour",
                "time_limit": "1h",
                "status": "active",
                "expires_at": "2000-01-01 00:00:00",
                "routeros_id": "*2",
            },
            router_id,
        )
        karte.update_voucher_sync_fields(
            voucher_id,
            router_id,
            {
                "activated_at": "1999-12-31 23:00:00",
                "first_login_mac": "AA:BB:CC:DD:EE:00",
                "expires_at": "2000-01-01 00:00:00",
            },
        )
        client = FakeRouterClient(
            users=[{"id": "*2", "name": "KT-STILL-THERE", "disabled": "false"}],
            sticky_delete=True,
        )

        karte.sync_router_vouchers_with_client(karte.get_router(router_id), client)

        voucher = karte.get_voucher(voucher_id, router_id)
        self.assertEqual(voucher["status"], "active")
        self.assertEqual(voucher["routeros_id"], "*2")
        self.assertEqual(voucher["retry_count"], 1)
        self.assertIn("still reports", voucher["last_error"])

    def test_shared_connection_helper_tests_and_reconciles(self):
        router_id = self.router()
        router = karte.get_router(router_id)
        fake = FakeRouterClient()
        with patch.object(karte, "RouterClient", return_value=fake):
            result = karte.test_and_reconcile_router(router, karte.router_to_settings(router))
        self.assertTrue(fake.tested)
        self.assertEqual(result["checked"], 0)

    def test_terminal_voucher_reappearance_is_removed_after_reboot(self):
        router_id = self.router()
        voucher_id = karte.insert_voucher(
            {
                "username": "KT-REBOOT",
                "password": "secret",
                "profile": "one-day",
                "time_limit": "1d",
                "status": "removed",
                "routeros_id": "",
                "removed_at": "2026-01-01 00:00:00",
            },
            router_id,
        )
        router = karte.get_router(router_id)
        client = FakeRouterClient(users=[{"id": "*9", "name": "KT-REBOOT", "disabled": "false"}])

        karte.sync_router_vouchers_with_client(router, client)

        self.assertEqual(client.users, [])
        voucher = karte.get_voucher(voucher_id, router_id)
        self.assertEqual(voucher["status"], "removed")
        self.assertEqual(voucher["routeros_id"], "")
        with closing(karte.get_db()) as db:
            audit = db.execute(
                "SELECT action FROM audit_logs WHERE entity_id = ? ORDER BY id DESC LIMIT 1",
                (voucher_id,),
            ).fetchone()
        self.assertEqual(audit["action"], "terminal-remove")

    def test_unrecognized_router_user_is_flagged_for_review(self):
        router_id = self.router()
        router = karte.get_router(router_id)
        client = FakeRouterClient(
            users=[{"id": "*77", "name": "manual-user", "profile": "default", "disabled": "false"}]
        )

        result = karte.sync_router_vouchers_with_client(router, client)

        self.assertEqual(result["unrecognized"], 1)
        self.assertEqual(len(client.users), 1)
        with closing(karte.get_db()) as db:
            issue = db.execute(
                """
                SELECT * FROM reconciliation_issues
                WHERE router_id = ? AND remote_name = ?
                """,
                (router_id, "manual-user"),
            ).fetchone()
        self.assertIsNotNone(issue)
        self.assertEqual(issue["status"], "open")
        self.assertEqual(issue["routeros_id"], "*77")


if __name__ == "__main__":
    unittest.main()
