import subprocess
import unittest
from unittest.mock import patch
from local_diagnostic import build_report, read_wifi


class DiagnosticTests(unittest.TestCase):
    @patch("local_diagnostic.shutil.which", return_value=None)
    def test_missing_api(self, _):
        self.assertEqual(read_wifi()[1], "unavailable")

    @patch("local_diagnostic.shutil.which", return_value="/bin/api")
    @patch("local_diagnostic.subprocess.run", side_effect=subprocess.TimeoutExpired("api", 15))
    def test_timeout(self, *_):
        self.assertEqual(read_wifi()[1], "timeout")

    @patch("local_diagnostic.shutil.which", return_value="/bin/api")
    @patch("local_diagnostic.subprocess.run")
    def test_bad_api_responses(self, run, _):
        for raw in ('not-json', '[]', '{"error":"denied"}'):
            run.return_value = subprocess.CompletedProcess([], 0, raw, "")
            self.assertEqual(read_wifi()[1], "error")
        run.return_value = subprocess.CompletedProcess([], 1, "", "denied")
        self.assertEqual(read_wifi()[1], "error")

    def test_no_invented_gateway_or_security(self):
        report = build_report({"ip": "192.0.2.5", "ssid": "Lab", "rssi": -60}, "ok", None)
        self.assertIsNone(report["connection"]["gateway"])
        self.assertIsNone(report["connection"]["security"])
        self.assertEqual(report["findings"], [])

    def test_manual_provenance_and_mismatch(self):
        report = build_report({"ip": "192.0.2.6"}, "ok", None,
                              {"cidr": "192.0.2.5/24", "security": "WPA/TKIP"})
        self.assertEqual(report["connection"]["network"], "192.0.2.0/24")
        self.assertTrue(report["warnings"])
        self.assertFalse(report["findings"][0]["verified_by_radio"])

    def test_redacted_identifiers_not_exported(self):
        report = build_report({"ssid": "<unknown ssid>", "ip": "0.0.0.0",
                               "bssid": "aa:bb:cc:dd:ee:ff", "mac_address": "secret"}, "ok", None)
        self.assertIsNone(report["connection"]["ssid"])
        self.assertIsNone(report["connection"]["ip"])
        self.assertNotIn("bssid", report["connection"])


if __name__ == "__main__":
    unittest.main()
