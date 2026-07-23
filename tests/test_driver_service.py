"""Tests for driver profile matching."""

from __future__ import annotations

import unittest

from app.core.driver_service import DriverService, PROFILES


class DriverServiceTests(unittest.TestCase):
    def test_rtl8188eus_usb_match(self) -> None:
        svc = DriverService()
        prof = svc._match_profile("Bus 001 Device 003: ID 0bda:8179 Realtek RTL8188EUS")
        self.assertIsNotNone(prof)
        assert prof is not None
        self.assertEqual(prof.id, "rtl8188eus")
        self.assertEqual(prof.apt_package, "realtek-rtl8188eus-dkms")

    def test_rtl8xxxu_chipset_keyword(self) -> None:
        svc = DriverService()
        prof = svc._match_profile("phy0 wlan0 rtl8xxxu Realtek Semiconductor Corp. RTL8188EUS")
        self.assertIsNotNone(prof)
        assert prof is not None
        self.assertEqual(prof.good_module, "8188eu")

    def test_profiles_have_packages(self) -> None:
        for p in PROFILES:
            self.assertTrue(p.apt_package)
            self.assertTrue(p.good_module)


if __name__ == "__main__":
    unittest.main()
