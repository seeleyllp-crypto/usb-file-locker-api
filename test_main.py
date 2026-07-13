import json
import hashlib
import os
import tempfile
import threading
import unittest
from pathlib import Path
from urllib import error, request

import main as api


TEST_SIGNING_SECRET = "vaultlink-regression-test-signing-secret"
TEST_ADMIN_TOKEN = "vaultlink-regression-test-admin-token"


def sample_report():
    return {
        "exported_at_utc": "2026-07-10T22:00:00Z",
        "defender_status": {
            "available": True,
            "AntivirusEnabled": True,
            "forbidden": "SECRET_DEFENDER_FIELD",
            "LastQuickScanSource": "SECRET_SCAN_SOURCE",
        },
        "usb_file_locker_audit": {
            "valid": True,
            "verification": "SECRET_VERIFICATION_FIELD",
            "events": [
                {
                    "sequence": 1,
                    "time_utc": "2026-07-10T22:00:00Z",
                    "event_id": "event-001",
                    "action": "lock",
                    "result": "success",
                    "hash": "a" * 64,
                    "previous_hash": "0" * 64,
                    "full_path": "C:/Private/secret.txt",
                    "file_contents": "SECRET_FILE_CONTENT",
                },
                {
                    "sequence": 2,
                    "time_utc": "2026-07-10T22:01:00Z",
                    "event_id": "SECRET-EVENT-ID",
                    "action": "SECRET_ACTION_FIELD",
                    "result": "success",
                    "hash": "b" * 64,
                    "previous_hash": "a" * 64,
                },
            ],
        },
        "pc_safety_check_audit": {
            "valid": True,
            "verification": "Valid",
            "events": [],
        },
        "password": "SECRET_PASSWORD_FIELD",
        "limitations": ["SECRET_LIMITATION_FIELD"],
    }


class VaultLinkApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old_signing_secret = os.environ.get("LICENSE_SIGNING_SECRET")
        cls.old_admin_token = os.environ.get("LICENSE_ADMIN_TOKEN")
        os.environ["LICENSE_SIGNING_SECRET"] = TEST_SIGNING_SECRET
        os.environ["LICENSE_ADMIN_TOKEN"] = TEST_ADMIN_TOKEN
        cls.server = api.ThreadingHTTPServer(("127.0.0.1", 0), api.ApiHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=5)
        if cls.old_signing_secret is None:
            os.environ.pop("LICENSE_SIGNING_SECRET", None)
        else:
            os.environ["LICENSE_SIGNING_SECRET"] = cls.old_signing_secret
        if cls.old_admin_token is None:
            os.environ.pop("LICENSE_ADMIN_TOKEN", None)
        else:
            os.environ["LICENSE_ADMIN_TOKEN"] = cls.old_admin_token

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="vaultlink_api_test_")
        api.AUDIT_EXPORT_DIR = Path(self.temp_dir.name)
        api.LICENSE_STATE_DIR = Path(self.temp_dir.name) / "license_state"
        api.UPDATE_DIR = Path(self.temp_dir.name) / "updates"
        api.UPDATE_MANIFEST_PATH = api.UPDATE_DIR / "windows-manifest.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def call(self, path, method="GET", payload=None, raw_body=None, headers=None):
        request_headers = dict(headers or {})
        if payload is not None:
            raw_body = json.dumps(payload).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        req = request.Request(
            self.base_url + path,
            data=raw_body,
            headers=request_headers,
            method=method,
        )
        try:
            with request.urlopen(req, timeout=10) as response:
                body = response.read()
                return response.status, json.loads(body.decode("utf-8")) if body else {}
        except error.HTTPError as exc:
            try:
                body = exc.read()
                return exc.code, json.loads(body.decode("utf-8")) if body else {}
            finally:
                exc.close()

    def call_bytes(self, path, headers=None):
        req = request.Request(self.base_url + path, headers=dict(headers or {}), method="GET")
        try:
            with request.urlopen(req, timeout=10) as response:
                return response.status, dict(response.headers.items()), response.read()
        except error.HTTPError as exc:
            try:
                return exc.code, dict(exc.headers.items()), exc.read()
            finally:
                exc.close()

    def publish_test_update(self):
        api.UPDATE_DIR.mkdir(parents=True, exist_ok=True)
        package = api.UPDATE_DIR / "VaultLink-Windows-9999.1.zip"
        package.write_bytes(b"PK-test-signed-update-package")
        manifest = {
            "schema_version": 1,
            "product": "USB File Locker",
            "platform": "windows-source",
            "version": "9999.1",
            "minimum_supported_version": "2026.07.10",
            "published_at_utc": "2026-07-11T15:00:00Z",
            "package_filename": package.name,
            "download_path": "/api/v1/updates/windows/download",
            "sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
            "size_bytes": package.stat().st_size,
            "signing_key_id": api.UPDATE_SIGNING_KEY_ID,
            "notes": ["Regression update"],
            "preserves_local_app_data": True,
            "signature": "A" * 86,
        }
        api.UPDATE_MANIFEST_PATH.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest, package

    def issue_and_activate(self, plan_id="personal-plus", machine_id="TEST-MACHINE"):
        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={"plan_id": plan_id, "customer_label": "Regression test"},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)
        status, activated = self.call(
            "/api/v1/licenses/activate",
            method="POST",
            payload={
                "license_key": issued["license_key"],
                "machine_id": machine_id,
                "machine_name": "Test PC",
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(activated["active"])
        return issued, activated

    def upload_report(self, issued, activated, machine_id="TEST-MACHINE", report=None):
        return self.call(
            "/api/v1/audit-exports",
            method="POST",
            payload={
                "license_key": issued["license_key"],
                "receipt": activated["receipt"],
                "machine_id": machine_id,
                "app_version": "test",
                "report": report or sample_report(),
            },
        )

    def test_public_shop_publishes_only_valid_hosted_checkout_links(self):
        env_names = [*api.SHOP_CHECKOUT_ENV_BY_PLAN.values(), "SHOP_CHECKOUT_ALLOWED_HOSTS"]
        previous = {name: os.environ.get(name) for name in env_names}
        try:
            for name in env_names:
                os.environ.pop(name, None)

            status, shop = self.call("/api/v1/shop")
            self.assertEqual(status, 200)
            self.assertEqual(shop["count"], 7)
            self.assertEqual(shop["configured_count"], 0)
            self.assertFalse(shop["ready"])
            self.assertFalse(shop["card_data_collected_by_vaultlink"])
            self.assertTrue(all(not item["checkout_available"] for item in shop["items"]))

            status, _headers, page = self.call_bytes("/shop")
            page_text = page.decode("utf-8")
            self.assertEqual(status, 200)
            self.assertIn("VaultLink Shop", page_text)
            self.assertEqual(page_text.count("NOT ON SALE YET"), 7)

            os.environ["SHOP_CHECKOUT_STARTER_URL"] = "https://buy.stripe.com/test_vaultlink_starter"
            os.environ["SHOP_CHECKOUT_HOME_URL"] = "http://buy.stripe.com/test_insecure"
            os.environ["SHOP_CHECKOUT_PERSONAL_PLUS_URL"] = "https://buy.stripe.com.evil.example/test_spoofed"
            os.environ["SHOP_CHECKOUT_FAMILY_SAFETY_URL"] = "https://buy.stripe.com/test_fragment#secret"
            os.environ["SHOP_CHECKOUT_SMALL_OFFICE_URL"] = "https://owner@buy.stripe.com/test_userinfo"
            os.environ["SHOP_CHECKOUT_FAMILY_OFFICE_URL"] = "https://buy.stripe.com:444/test_port"
            os.environ["SHOP_CHECKOUT_PRO_BASELINE_URL"] = "https://buy.stripe.com/"

            status, shop = self.call("/api/v1/shop")
            self.assertEqual(status, 200)
            self.assertEqual(shop["configured_count"], 1)
            starter = next(item for item in shop["items"] if item["id"] == "starter")
            self.assertTrue(starter["checkout_available"])
            self.assertEqual(starter["checkout_url"], os.environ["SHOP_CHECKOUT_STARTER_URL"])
            self.assertTrue(
                all(
                    not item["checkout_available"]
                    for item in shop["items"]
                    if item["id"] != "starter"
                )
            )

            status, health = self.call("/health")
            self.assertEqual(status, 200)
            self.assertEqual(health["shop_checkout_links_configured"], 1)
            self.assertFalse(health["shop_card_data_collected_by_vaultlink"])

            status, dashboard = self.call(
                "/api/v1/admin/dashboard",
                headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
            )
            self.assertEqual(status, 200)
            self.assertEqual(dashboard["shop"]["configured"], 1)
            self.assertEqual(dashboard["shop"]["total"], 7)
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def test_license_issue_activate_verify_and_header_only_admin(self):
        status, denied = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={"plan_id": "family-safety", "admin_token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")

        issued, activated = self.issue_and_activate("family-safety")
        self.assertTrue(issued["license_key"].startswith("vlk1."))
        self.assertTrue(activated["receipt"].startswith("vlr1."))

        status, verified = self.call(
            "/api/v1/licenses/verify",
            method="POST",
            payload={
                "license_key": issued["license_key"],
                "receipt": activated["receipt"],
                "machine_id": "TEST-MACHINE",
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(verified["active"])

        status, wrong_machine = self.call(
            "/api/v1/licenses/verify",
            method="POST",
            payload={
                "license_key": issued["license_key"],
                "receipt": activated["receipt"],
                "machine_id": "OTHER-MACHINE",
            },
        )
        self.assertEqual(status, 200)
        self.assertFalse(wrong_machine["active"])
        self.assertEqual(wrong_machine["status"], "wrong_machine")

    def test_automatic_sync_reports_policy_and_enforces_revocation(self):
        issued, activated = self.issue_and_activate("personal-plus", "SYNC-PC")
        request_payload = {
            "license_key": issued["license_key"],
            "receipt": activated["receipt"],
            "machine_id": "SYNC-PC",
            "app_version": "2026.07.12.2",
        }
        status, synced = self.call(
            "/api/v1/licenses/sync",
            method="POST",
            payload=request_payload,
        )
        self.assertEqual(status, 200)
        self.assertTrue(synced["active"])
        self.assertEqual(synced["api_version"], api.API_VERSION)
        self.assertTrue(synced["sync"]["automatic"])
        self.assertEqual(synced["sync"]["recommended_interval_seconds"], api.LICENSE_SYNC_INTERVAL_SECONDS)
        self.assertEqual(len(synced["sync"]["decision_id"]), 16)
        status, devices = self.call(
            f"/api/v1/admin/licenses/{issued['license']['license_id']}/devices",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(devices["items"][0]["app_version"], "2026.07.12.2")
        self.assertTrue(devices["items"][0]["last_seen_at_utc"])

        status, revoked = self.call(
            "/api/v1/licenses/revoke",
            method="POST",
            payload={"license_key": issued["license_key"]},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertTrue(revoked["revoked"])
        status, synced = self.call(
            "/api/v1/licenses/sync",
            method="POST",
            payload=request_payload,
        )
        self.assertEqual(status, 200)
        self.assertFalse(synced["active"])
        self.assertEqual(synced["status"], "revoked")
        self.assertEqual(synced["sync"]["decision"], "revoked")

    def test_encrypted_bug_inbox_owner_actions_and_customer_reply(self):
        issued, activated = self.issue_and_activate("starter", "BUG-REPORT-PC")
        auth_payload = {
            "license_key": issued["license_key"],
            "receipt": activated["receipt"],
            "machine_id": "BUG-REPORT-PC",
            "app_version": "2026.07.12.3",
        }
        private_message = "The lock button stopped after I selected two sample files."
        status, created = self.call(
            "/api/v1/support-tickets",
            method="POST",
            payload={
                **auth_payload,
                "category": "bug",
                "subject": "Lock button stopped",
                "message": private_message,
                "steps": "Open app\nAdd two files\nClick LOCK COPY",
            },
        )
        self.assertEqual(status, 201)
        ticket_id = created["ticket"]["ticket_id"]
        self.assertTrue(ticket_id.startswith("TKT-"))
        stored_path = api.support_ticket_path(ticket_id)
        stored_text = stored_path.read_text(encoding="utf-8")
        self.assertNotIn(private_message, stored_text)
        self.assertNotIn("Lock button stopped", stored_text)
        self.assertNotIn("BUG-REPORT-PC", stored_text)
        self.assertNotIn(issued["license_key"], stored_text)

        status, mine = self.call(
            "/api/v1/support-tickets/mine",
            method="POST",
            payload=auth_payload,
        )
        self.assertEqual(status, 200)
        self.assertEqual(mine["count"], 1)
        self.assertEqual(mine["items"][0]["status"], "open")

        status, denied = self.call("/api/v1/admin/support-tickets")
        self.assertEqual(status, 403)
        status, inbox = self.call(
            "/api/v1/admin/support-tickets",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(inbox["items"][0]["message"], private_message)

        owner_reply = "Thanks. I reproduced this and am working on the fix."
        owner_note = "Regression test against multi-file queue"
        status, updated = self.call(
            "/api/v1/admin/support-tickets/action",
            method="POST",
            payload={
                "ticket_id": ticket_id,
                "status": "in_progress",
                "owner_reply": owner_reply,
                "owner_note": owner_note,
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(updated["ticket"]["status"], "in_progress")
        self.assertEqual(updated["ticket"]["owner_note"], owner_note)
        self.assertNotIn(owner_reply, stored_path.read_text(encoding="utf-8"))

        status, mine = self.call(
            "/api/v1/support-tickets/mine",
            method="POST",
            payload=auth_payload,
        )
        self.assertEqual(status, 200)
        self.assertEqual(mine["items"][0]["owner_reply"], owner_reply)
        self.assertNotIn("owner_note", mine["items"][0])

        status, dashboard = self.call(
            "/api/v1/admin/dashboard",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(dashboard["support_tickets"]["total"], 1)

        status, deleted = self.call(
            "/api/v1/admin/support-tickets/delete",
            method="POST",
            payload={"ticket_id": ticket_id},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertTrue(deleted["deleted"])
        status, mine = self.call(
            "/api/v1/support-tickets/mine",
            method="POST",
            payload=auth_payload,
        )
        self.assertEqual(status, 200)
        self.assertEqual(mine["count"], 0)

    def test_damaged_support_ticket_does_not_break_owner_dashboard(self):
        issued, activated = self.issue_and_activate("starter", "DAMAGED-TICKET-PC")
        status, created = self.call(
            "/api/v1/support-tickets",
            method="POST",
            payload={
                "license_key": issued["license_key"],
                "receipt": activated["receipt"],
                "machine_id": "DAMAGED-TICKET-PC",
                "category": "bug",
                "subject": "Damaged ticket test",
                "message": "This ticket will be damaged after it is safely encrypted.",
            },
        )
        self.assertEqual(status, 201)
        path = api.support_ticket_path(created["ticket"]["ticket_id"])
        record = json.loads(path.read_text(encoding="utf-8"))
        record["private_blob"] = record["private_blob"][:-1] + ("A" if record["private_blob"][-1] != "A" else "B")
        path.write_text(json.dumps(record), encoding="utf-8")

        status, inbox = self.call(
            "/api/v1/admin/support-tickets",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(inbox["count"], 0)
        self.assertEqual(inbox["damaged_count"], 1)
        status, dashboard = self.call(
            "/api/v1/admin/dashboard",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(dashboard["support_tickets"]["total"], 0)

    def test_license_notes_deactivation_revocation_and_restore(self):
        private_note = "Renew after family laptop setup"
        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={
                "plan_id": "family-safety",
                "customer_label": "Test customer",
                "license_note": private_note,
            },
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)
        self.assertNotIn("license_note", issued)
        license_key = issued["license_key"]

        record_files = list((api.LICENSE_STATE_DIR / "licenses").glob("*.json"))
        self.assertEqual(len(record_files), 1)
        stored_text = record_files[0].read_text(encoding="utf-8")
        self.assertNotIn(private_note, stored_text)
        self.assertNotIn(license_key, stored_text)

        status, denied = self.call("/api/v1/admin/licenses")
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")
        status, inventory = self.call(
            "/api/v1/admin/licenses",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(inventory["count"], 1)
        self.assertEqual(inventory["items"][0]["license_note"], private_note)
        self.assertEqual(inventory["items"][0]["license_key"], license_key)

        status, activated = self.call(
            "/api/v1/licenses/activate",
            method="POST",
            payload={"license_key": license_key, "machine_id": "REMOVE-PC"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(activated["active"])
        status, deactivated = self.call(
            "/api/v1/licenses/deactivate",
            method="POST",
            payload={
                "license_key": license_key,
                "receipt": activated["receipt"],
                "machine_id": "REMOVE-PC",
                "app_version": "test",
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(deactivated["deactivated"])
        status, verification = self.call(
            "/api/v1/licenses/verify",
            method="POST",
            payload={
                "license_key": license_key,
                "receipt": activated["receipt"],
                "machine_id": "REMOVE-PC",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(verification["status"], "deactivated")

        status, reactivated = self.call(
            "/api/v1/licenses/activate",
            method="POST",
            payload={"license_key": license_key, "machine_id": "REMOVE-PC"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(reactivated["active"])
        self.assertNotEqual(reactivated["receipt"], activated["receipt"])

        status, denied = self.call(
            "/api/v1/licenses/revoke",
            method="POST",
            payload={"license_key": license_key},
        )
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")
        status, revoked = self.call(
            "/api/v1/licenses/revoke",
            method="POST",
            payload={"license_key": license_key, "revocation_note": "Customer requested removal"},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertTrue(revoked["revoked"])
        status, verification = self.call(
            "/api/v1/licenses/verify",
            method="POST",
            payload={
                "license_key": license_key,
                "receipt": reactivated["receipt"],
                "machine_id": "REMOVE-PC",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(verification["status"], "revoked")

        status, restored = self.call(
            "/api/v1/licenses/restore",
            method="POST",
            payload={"license_key": license_key},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertTrue(restored["restored"])
        status, verification = self.call(
            "/api/v1/licenses/verify",
            method="POST",
            payload={
                "license_key": license_key,
                "receipt": reactivated["receipt"],
                "machine_id": "REMOVE-PC",
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(verification["active"])

        status, noted = self.call(
            "/api/v1/licenses/note",
            method="POST",
            payload={"license_key": license_key, "license_note": "Updated private note"},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(noted["license"]["license_note"], "Updated private note")

    def test_device_limit_dashboard_and_admin_reset(self):
        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={"plan_id": "home", "max_devices": 1, "license_note": "Seat test"},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)
        key = issued["license_key"]

        status, first = self.call(
            "/api/v1/licenses/activate",
            method="POST",
            payload={"license_key": key, "machine_id": "FIRST-PC", "machine_name": "Private PC name"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(first["active"])
        self.assertEqual(first["device_usage"], {"active": 1, "maximum": 1})

        status, denied = self.call(
            "/api/v1/licenses/activate",
            method="POST",
            payload={"license_key": key, "machine_id": "SECOND-PC"},
        )
        self.assertEqual(status, 200)
        self.assertFalse(denied["active"])
        self.assertEqual(denied["status"], "device_limit")

        activation_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (api.LICENSE_STATE_DIR / "activations").rglob("*.json")
        )
        self.assertNotIn("FIRST-PC", activation_text)
        self.assertNotIn("Private PC name", activation_text)

        status, inventory = self.call(
            "/api/v1/admin/licenses",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(inventory["items"][0]["active_devices"], 1)

        status, dashboard = self.call(
            "/api/v1/admin/dashboard",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(dashboard["licenses"]["active"], 1)
        self.assertEqual(dashboard["devices"], {"active": 1, "capacity": 1})
        self.assertEqual(dashboard["audit_exports"]["total"], 0)

        status, denied = self.call(
            "/api/v1/licenses/reset-devices",
            method="POST",
            payload={"license_key": key},
        )
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")

        status, reset = self.call(
            "/api/v1/licenses/reset-devices",
            method="POST",
            payload={"license_key": key},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(reset["devices_reset"], 1)
        self.assertEqual(reset["license"]["active_devices"], 0)

        status, old_receipt = self.call(
            "/api/v1/licenses/verify",
            method="POST",
            payload={"license_key": key, "receipt": first["receipt"], "machine_id": "FIRST-PC"},
        )
        self.assertEqual(status, 200)
        self.assertFalse(old_receipt["active"])
        self.assertEqual(old_receipt["status"], "reset")

        status, second = self.call(
            "/api/v1/licenses/activate",
            method="POST",
            payload={"license_key": key, "machine_id": "SECOND-PC"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(second["active"])
        self.assertEqual(second["device_usage"]["active"], 1)

    def test_admin_lists_and_removes_one_anonymous_device(self):
        status, issued = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={"plan_id": "family-safety", "max_devices": 2},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 201)
        key = issued["license_key"]
        activations = {}
        for machine_id in ("FIRST-PRIVATE-PC", "SECOND-PRIVATE-PC"):
            status, activated = self.call(
                "/api/v1/licenses/activate",
                method="POST",
                payload={"license_key": key, "machine_id": machine_id, "machine_name": machine_id},
            )
            self.assertEqual(status, 200)
            self.assertTrue(activated["active"])
            activations[machine_id] = activated

        license_id = issued["license"]["license_id"]
        status, devices = self.call(
            f"/api/v1/admin/licenses/{license_id}/devices",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(devices["active_count"], 2)
        serialized = json.dumps(devices)
        self.assertNotIn("FIRST-PRIVATE-PC", serialized)
        self.assertNotIn("SECOND-PRIVATE-PC", serialized)

        first_hash = api.anonymous_machine_hash("FIRST-PRIVATE-PC")
        status, removed = self.call(
            "/api/v1/licenses/remove-device",
            method="POST",
            payload={"license_key": key, "machine_hash": first_hash},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertTrue(removed["removed"])
        self.assertEqual(removed["license"]["active_devices"], 1)

        status, first_sync = self.call(
            "/api/v1/licenses/sync",
            method="POST",
            payload={
                "license_key": key,
                "receipt": activations["FIRST-PRIVATE-PC"]["receipt"],
                "machine_id": "FIRST-PRIVATE-PC",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(first_sync["status"], "removed")
        status, second_sync = self.call(
            "/api/v1/licenses/sync",
            method="POST",
            payload={
                "license_key": key,
                "receipt": activations["SECOND-PRIVATE-PC"]["receipt"],
                "machine_id": "SECOND-PRIVATE-PC",
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(second_sync["active"])

    def test_audit_export_strips_private_fields_and_uses_bearer_token(self):
        issued, activated = self.issue_and_activate("personal-plus")
        status, uploaded = self.upload_report(issued, activated)
        self.assertEqual(status, 201)
        self.assertNotIn("token=", uploaded["download_path"])
        self.assertEqual(uploaded["breach_summary"]["level"], "clear")

        status, denied = self.call(uploaded["download_path"])
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")

        status, downloaded = self.call(
            uploaded["download_path"],
            headers={"Authorization": f"Bearer {uploaded['download_token']}"},
        )
        self.assertEqual(status, 200)
        event = downloaded["report"]["usb_file_locker_audit"]["events"][0]
        self.assertEqual(
            set(event),
            {"sequence", "time_utc", "event_id", "action", "result", "hash", "previous_hash"},
        )
        unknown_event = downloaded["report"]["usb_file_locker_audit"]["events"][1]
        self.assertEqual(unknown_event["action"], "unknown_action")
        self.assertRegex(unknown_event["event_id"], r"^[0-9a-f]{16}$")
        serialized = json.dumps(downloaded)
        for forbidden in (
            "SECRET_FILE_CONTENT",
            "SECRET_PASSWORD_FIELD",
            "SECRET_DEFENDER_FIELD",
            "SECRET_SCAN_SOURCE",
            "SECRET_VERIFICATION_FIELD",
            "SECRET_ACTION_FIELD",
            "SECRET-EVENT-ID",
            "SECRET_LIMITATION_FIELD",
            "C:/Private/secret.txt",
        ):
            self.assertNotIn(forbidden, serialized)

        token = uploaded["download_token"]
        tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
        status, denied = self.call(
            uploaded["download_path"],
            headers={"Authorization": f"Bearer {tampered}"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")

    def test_starter_plan_cannot_upload_audit_report(self):
        issued, activated = self.issue_and_activate("starter")
        status, denied = self.upload_report(issued, activated)
        self.assertEqual(status, 403)
        self.assertIn("does not include", denied["message"])

    def test_admin_can_list_and_download_stored_breach_reports(self):
        issued, activated = self.issue_and_activate("family-safety")
        report = sample_report()
        report["usb_file_locker_audit"]["events"].append(
            {
                "sequence": 3,
                "time_utc": "2026-07-10T22:02:00Z",
                "event_id": "0123456789abcdef",
                "action": "owner_usb_removed",
                "result": "success",
                "hash": "c" * 64,
                "previous_hash": "b" * 64,
            }
        )
        status, uploaded = self.upload_report(issued, activated, report=report)
        self.assertEqual(status, 201)
        self.assertEqual(uploaded["breach_summary"]["level"], "high")

        status, denied = self.call("/api/v1/admin/audit-exports")
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")

        status, listing = self.call(
            "/api/v1/admin/audit-exports",
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(listing["count"], 1)
        item = listing["items"][0]
        self.assertEqual(item["export_id"], uploaded["export_id"])
        self.assertEqual(item["breach_summary"]["level"], "high")
        self.assertEqual(item["event_count"], 3)
        self.assertNotIn("download_token", json.dumps(listing))

        status, denied = self.call(item["download_path"])
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")

        status, downloaded = self.call(
            item["download_path"],
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(downloaded["export_id"], uploaded["export_id"])
        self.assertEqual(downloaded["breach_summary"]["level"], "high")
        serialized = json.dumps(downloaded)
        self.assertNotIn("SECRET_FILE_CONTENT", serialized)
        self.assertNotIn("C:/Private/secret.txt", serialized)

        status, denied = self.call(
            "/api/v1/admin/audit-exports/download-link",
            method="POST",
            payload={"export_id": item["export_id"]},
        )
        self.assertEqual(status, 403)
        status, link = self.call(
            "/api/v1/admin/audit-exports/download-link",
            method="POST",
            payload={"export_id": item["export_id"]},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertIn("?token=vla1.", link["download_path"])
        self.assertNotIn(TEST_ADMIN_TOKEN, link["download_path"])
        status, downloaded = self.call(link["download_path"])
        self.assertEqual(status, 200)
        self.assertEqual(downloaded["export_id"], item["export_id"])

    def test_signed_update_manifest_and_package_endpoints(self):
        manifest, package = self.publish_test_update()
        status, response = self.call("/api/v1/updates/windows")
        self.assertEqual(status, 200)
        self.assertEqual(response["update"]["version"], manifest["version"])
        self.assertEqual(response["update"]["sha256"], manifest["sha256"])
        self.assertTrue(response["security"]["automatic_install_requires_user_confirmation"])

        status, headers, body = self.call_bytes("/api/v1/updates/windows/download")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/zip")
        self.assertEqual(body, package.read_bytes())

        package.write_bytes(b"tampered")
        status, response = self.call("/api/v1/updates/windows")
        self.assertEqual(status, 503)
        self.assertEqual(response["error"], "update_unavailable")

    def test_route_limits_content_type_and_unknown_route(self):
        oversized = b'{' + b'"padding":"' + (b"x" * api.MAX_LICENSE_JSON_BODY_BYTES) + b'"}'
        status, response = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            raw_body=oversized,
            headers={
                "Content-Type": "application/json",
                "X-License-Admin-Token": TEST_ADMIN_TOKEN,
            },
        )
        self.assertEqual(status, 413)
        self.assertEqual(response["error"], "request_too_large")

        status, response = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            raw_body=b"plan_id=family-safety",
            headers={
                "Content-Type": "text/plain",
                "X-License-Admin-Token": TEST_ADMIN_TOKEN,
            },
        )
        self.assertEqual(status, 415)
        self.assertEqual(response["error"], "unsupported_media_type")

        status, response = self.call(
            "/api/v1/not-a-route",
            method="POST",
            payload={"anything": True},
        )
        self.assertEqual(status, 404)
        self.assertEqual(response["error"], "not_found")

    def test_download_rejects_damaged_stored_identity(self):
        issued, activated = self.issue_and_activate("personal-plus")
        status, uploaded = self.upload_report(issued, activated)
        self.assertEqual(status, 201)
        stored_path = api.audit_export_path(uploaded["export_id"])
        stored = json.loads(stored_path.read_text(encoding="utf-8"))
        stored["source"]["machine_hash"] = "0" * 16
        stored_path.write_text(json.dumps(stored), encoding="utf-8")

        status, denied = self.call(
            uploaded["download_path"],
            headers={"Authorization": f"Bearer {uploaded['download_token']}"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "forbidden")

    def test_field_and_token_length_limits(self):
        status, response = self.call(
            "/api/v1/licenses/issue",
            method="POST",
            payload={"plan_id": "family-safety", "customer_label": "x" * 161},
            headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 400)
        self.assertIn("160", response["message"])

        with self.assertRaisesRegex(ValueError, "too large"):
            api.verify_token("vlk1." + ("x" * api.MAX_SIGNED_TOKEN_CHARS), api.LICENSE_KEY_PREFIX)

    def test_all_seven_ranks_are_public_and_ordered(self):
        status, response = self.call("/api/v1/ranks")
        self.assertEqual(status, 200)
        self.assertEqual(response["count"], 7)
        items = response["items"]
        self.assertEqual(
            [item["id"] for item in items],
            [
                "starter",
                "home",
                "personal-plus",
                "family-safety",
                "small-office",
                "family-office",
                "pro-baseline",
            ],
        )
        self.assertEqual([item["rank"] for item in items], list(range(1, 8)))
        self.assertEqual(items[1]["price_label"], "$10-$25")
        self.assertEqual(items[5]["price_max_usd"], 3000)
        self.assertIsNone(items[6]["price_max_usd"])
        self.assertIn("pro-baseline-pack", items[6]["entitlements"])
        self.assertGreater(len(items[6]["entitlements"]), len(items[5]["entitlements"]))

    def test_legacy_plan_ids_issue_equivalent_canonical_ranks(self):
        expected = {
            "plus": "personal-plus",
            "pro": "family-safety",
            "signature": "small-office",
        }
        for legacy_id, canonical_id in expected.items():
            with self.subTest(legacy_id=legacy_id):
                status, response = self.call(
                    "/api/v1/licenses/issue",
                    method="POST",
                    payload={"plan_id": legacy_id},
                    headers={"X-License-Admin-Token": TEST_ADMIN_TOKEN},
                )
                self.assertEqual(status, 201)
                self.assertEqual(response["license"]["plan_id"], canonical_id)
                self.assertEqual(response["plan"]["id"], canonical_id)


if __name__ == "__main__":
    unittest.main(verbosity=2)
