from contextlib import closing

import app as karte


class FakeRouterClient:
    def __init__(self, users=None, delete_error=None):
        self.users = [dict(user) for user in (users or [])]
        self.delete_error = delete_error

    def list_hotspot_users(self):
        return [dict(user) for user in self.users]

    def list_active_hotspot_users(self):
        return []

    def remove_active_hotspot_sessions(self, username):
        return None

    def delete_voucher(self, routeros_id, username):
        if self.delete_error:
            raise self.delete_error
        self.users = [
            user
            for user in self.users
            if karte.routeros_item_id(user) != routeros_id and user.get("name") != username
        ]

    def create_voucher(self, voucher):
        routeros_id = f"*{len(self.users) + 1}"
        self.users.append({"id": routeros_id, "name": voucher["username"]})
        return routeros_id

    def disable_voucher(self, routeros_id, username):
        return None

    def enable_voucher(self, routeros_id, username):
        return None

    def bind_voucher_to_mac(self, routeros_id, username, mac_address):
        return None


def main() -> None:
    router_id = karte.insert_router(
        {
            "name": "MySQL Test Router",
            "router_ip": "192.168.88.1",
            "api_port": "8728",
            "router_username": "admin",
            "router_password": "router-secret",
        }
    )
    router = karte.get_router(router_id)

    retry_id = karte.insert_voucher(
        {
            "username": "MYSQL-RETRY",
            "password": "secret",
            "profile": "one-hour",
            "time_limit": "1h",
            "status": "active",
            "expires_at": "2000-01-01 00:00:00",
            "routeros_id": "*1",
        },
        router_id,
    )
    karte.update_voucher_sync_fields(
        retry_id,
        router_id,
        {
            "activated_at": "1999-12-31 23:00:00",
            "first_login_mac": "AA:BB:CC:DD:EE:FF",
            "expires_at": "2000-01-01 00:00:00",
        },
    )
    failed_client = FakeRouterClient(
        users=[{"id": "*1", "name": "MYSQL-RETRY"}],
        delete_error=RuntimeError("simulated MySQL integration deletion failure"),
    )
    karte.sync_router_vouchers_with_client(router, failed_client)
    retry_voucher = karte.get_voucher(retry_id, router_id)
    assert retry_voucher["status"] == "active"
    assert retry_voucher["routeros_id"] == "*1"
    assert int(retry_voucher["retry_count"]) == 1

    terminal_id = karte.insert_voucher(
        {
            "username": "MYSQL-REBOOT",
            "password": "secret",
            "profile": "one-day",
            "time_limit": "1d",
            "status": "removed",
        },
        router_id,
    )
    reboot_client = FakeRouterClient(users=[{"id": "*9", "name": "MYSQL-REBOOT"}])
    karte.sync_router_vouchers_with_client(router, reboot_client)
    assert reboot_client.users == []
    assert karte.get_voucher(terminal_id, router_id)["status"] == "removed"

    unknown_client = FakeRouterClient(users=[{"id": "*77", "name": "manual-router-user"}])
    result = karte.sync_router_vouchers_with_client(router, unknown_client)
    assert result["unrecognized"] == 1
    with closing(karte.get_db()) as db:
        issue = db.execute(
            "SELECT status FROM reconciliation_issues WHERE router_id = ? AND remote_name = ?",
            (router_id, "manual-router-user"),
        ).fetchone()
    assert issue and issue["status"] == "open"


if __name__ == "__main__":
    main()
