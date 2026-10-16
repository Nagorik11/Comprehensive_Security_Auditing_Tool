import contextlib
import io
import json
import unittest
from unittest.mock import patch

import local_diagnostic
from linux_local import read_linux, split_nmcli


ADDRESSES = [
    {"ifname": "eth0", "operstate": "UP", "addr_info": [
        {"family": "inet", "local": "198.51.100.5", "prefixlen": 24, "scope": "global"}]},
    {"ifname": "wlan0", "operstate": "UP", "addr_info": [
        {"family": "inet", "local": "192.0.2.5", "prefixlen": 24, "scope": "global"}]},
]
ROUTES = [{"dev": "eth0", "gateway": "198.51.100.1", "metric": 600},
          {"dev": "wlan0", "gateway": "192.0.2.1", "metric": 100}]


class LinuxTests(unittest.TestCase):
    def run_snapshot(self, interface=None, routes=None, nmcli=True, command_failure=False):
        self.commands = []

        def output(args, timeout=8):
            self.commands.append(args)
            if command_failure:
                return None, "ip devolvió un error; acceso denegado."
            if args[0] == "ip":
                return json.dumps(ADDRESSES if "address" in args else
                                  ROUTES if routes is None else routes), None
            if "show" in args:
                if args[-1] == "eth0":
                    return "GENERAL.TYPE:ethernet\nIP4.GATEWAY:198.51.100.1\n", None
                return "GENERAL.TYPE:wifi\nIP4.GATEWAY:192.0.2.1\nIP4.DNS[1]:192.0.2.53\n", None
            return r"*:Lab\:norte\\wifi:77:WPA2:5180 MHz" + "\n", None

        with patch("linux_local.command_output", side_effect=output), \
                patch("linux_local.shutil.which", return_value="/bin/nmcli" if nmcli else None), \
                patch("linux_local.system_dns", return_value=["127.0.0.53"]):
            return read_linux(interface)

    def test_route_selection_and_cached_wifi(self):
        data, status, error = self.run_snapshot()
        self.assertEqual(data["interface"], "wlan0")
        self.assertEqual(data["gateway"], "192.0.2.1")
        self.assertEqual(data["ssid"], "Lab:norte\\wifi")
        self.assertEqual(data["signal_percent"], 77)
        self.assertNotIn("rssi", data)
        self.assertEqual(data["dns"], ["192.0.2.53"])
        self.assertEqual(data["system_dns"], ["127.0.0.53"])
        self.assertEqual(data["_sources"]["security"], "nmcli-cache")
        self.assertEqual(status, "partial")
        report = local_diagnostic.build_report(data, status, error, backend="linux")
        self.assertEqual(report["connection"]["network"], "192.0.2.0/24")
        self.assertEqual(report["sources"]["network"], "derived_from_ip_cidr")
        self.assertEqual(report["findings"], [])
        wifi_command = self.commands[-1]
        self.assertEqual(wifi_command[-2:], ["--rescan", "no"])

    def test_explicit_interface_does_not_mix_other_network(self):
        data, _, _ = self.run_snapshot("eth0")
        self.assertEqual(data["ip"], "198.51.100.5")
        self.assertEqual(data["gateway"], "198.51.100.1")
        self.assertNotIn("ssid", data)
        self.assertFalse(any("wifi" in command for command in self.commands))

    def test_missing_nmcli_still_has_ip(self):
        data, status, _ = self.run_snapshot(nmcli=False)
        self.assertEqual(data["ip"], "192.0.2.5")
        self.assertEqual(status, "partial")
        self.assertNotIn("dns", data)

    def test_no_gateway_is_inferred_from_subnet(self):
        data, _, _ = self.run_snapshot("wlan0", routes=[], nmcli=False)
        self.assertEqual(data["cidr"], "192.0.2.5/24")
        self.assertNotIn("gateway", data)

    def test_permission_denied(self):
        data, status, error = self.run_snapshot(command_failure=True)
        self.assertEqual(data, {})
        self.assertEqual(status, "unavailable")
        self.assertIn("denegado", error)

    def test_unknown_interface(self):
        data, status, _ = self.run_snapshot("nonexistent0")
        self.assertEqual(data, {})
        self.assertEqual(status, "unavailable")
        self.assertEqual(len(self.commands), 1)

    def test_escaped_fields(self):
        self.assertEqual(split_nmcli(r"*:Cafe\:A\\B:50:WPA2:2412 MHz"),
                         ["*", "Cafe:A\\B", "50", "WPA2", "2412 MHz"])

    @patch("local_diagnostic.platform.system", return_value="Linux")
    @patch("local_diagnostic.os.environ", {})
    @patch("local_diagnostic.shutil.which", return_value=None)
    @patch("linux_local.read_linux", return_value=({}, "unavailable", "Permiso denegado"))
    def test_auto_backend_reports_restrictions_without_termux_advice(self, read, *_):
        with patch("sys.argv", ["local_diagnostic.py", "--local-only"]), \
                contextlib.redirect_stdout(io.StringIO()) as stream:
            local_diagnostic.main()
        result = json.loads(stream.getvalue())
        self.assertEqual(result["backend"], "linux")
        self.assertIsNone(result["connection"]["ip"])
        self.assertEqual(result["warnings"], ["Permiso denegado"])
        read.assert_called_once_with(None)


if __name__ == "__main__":
    unittest.main()
