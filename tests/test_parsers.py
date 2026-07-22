"""Unit tests for parsers (no aircrack-ng required)."""

from __future__ import annotations

import unittest

from app.core.parsers import (
    aircrack_reports_handshake,
    handshake_from_airodump_line,
    parse_aircrack_key,
    parse_airmon_monitor_iface,
    parse_airodump_csv,
    parse_wireless_interfaces,
)


SAMPLE_CSV = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:DD:EE:FF, 2024-01-01 00:00:00, 2024-01-01 00:01:00, 6, 54, WPA2, CCMP, PSK, -45, 10, 0, 0.0.0.0, 4, Test, 

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
11:22:33:44:55:66, 2024-01-01 00:00:30, 2024-01-01 00:01:00, -60, 12, AA:BB:CC:DD:EE:FF,
"""


class ParserTests(unittest.TestCase):
    def test_iwconfig_ifaces(self) -> None:
        out = """wlan0     IEEE 802.11  ESSID:off/any
eth0      no wireless extensions.
"""
        self.assertEqual(parse_wireless_interfaces(out), ["wlan0"])

    def test_airodump_csv(self) -> None:
        aps, stas = parse_airodump_csv(SAMPLE_CSV)
        self.assertEqual(len(aps), 1)
        self.assertEqual(aps[0].bssid, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(aps[0].essid, "Test")
        self.assertEqual(aps[0].channel, "6")
        self.assertEqual(len(stas), 1)
        self.assertEqual(stas[0].station_mac, "11:22:33:44:55:66")

    def test_airmon_iface(self) -> None:
        out = "monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon"
        self.assertEqual(parse_airmon_monitor_iface(out), "wlan0mon")

    def test_handshake_line(self) -> None:
        line = " CH  6 ][ Elapsed: 12 s ][ 2024-01-01 00:00 ][ WPA handshake: AA:BB:CC:DD:EE:FF"
        self.assertEqual(
            handshake_from_airodump_line(line),
            "AA:BB:CC:DD:EE:FF",
        )

    def test_aircrack_key(self) -> None:
        out = "KEY FOUND! [ hunter2 ]"
        self.assertEqual(parse_aircrack_key(out), "hunter2")

    def test_handshake_count(self) -> None:
        self.assertTrue(aircrack_reports_handshake("Opening capture.cap\n1 handshake"))
        self.assertFalse(aircrack_reports_handshake("No networks found"))


if __name__ == "__main__":
    unittest.main()
