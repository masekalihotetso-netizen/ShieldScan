import base64
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as app_module  # noqa: E402


class AppRoutes(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()
        with app_module._lock:
            app_module._reports.clear()
            app_module._rooms.clear()

    def test_index_and_mail_providers(self):
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"ShieldScan", page.data)

        providers = self.client.get("/api/mail/providers")
        self.assertEqual(providers.status_code, 200)
        self.assertIn("gmail", providers.get_json())

    def test_text_scan_report_and_missing_report(self):
        report = {"id": "test-report", "filename": "pasted-text.txt", "score": 5}
        with patch.object(app_module.scanner, "scan_file", return_value=report):
            response = self.client.post("/api/scan", data={"text": "Hello"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), report)
        self.assertEqual(self.client.get("/api/report/test-report").get_json(), report)
        self.assertEqual(self.client.get("/api/report/missing").status_code, 404)

    def test_chat_relay_and_input_validation(self):
        public_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "A" * 43,
            "y": "B" * 43,
        }
        for name in ("Alice", "Bob"):
            response = self.client.post(
                "/api/chat/join",
                json={"room": "test-room", "name": name, "pub": public_key},
            )
            self.assertEqual(response.status_code, 200)

        iv = base64.b64encode(b"\0" * 12).decode("ascii")
        ciphertext = base64.b64encode(b"\0" * 16).decode("ascii")
        sent = self.client.post(
            "/api/chat/send",
            json={"room": "test-room", "from": "Alice", "iv": iv, "ct": ciphertext},
        )
        self.assertEqual(sent.status_code, 200)

        poll = self.client.get("/api/chat/poll?room=test-room&after=0")
        self.assertEqual(poll.status_code, 200)
        self.assertEqual(poll.get_json()["msgs"][0]["id"], sent.get_json()["id"])
        self.assertEqual(len(poll.get_json()["users"]), 2)

        invalid = self.client.post(
            "/api/chat/send",
            json={"room": "test-room", "from": "Mallory", "iv": iv, "ct": ciphertext},
        )
        self.assertEqual(invalid.status_code, 403)


if __name__ == "__main__":
    unittest.main(verbosity=2)
