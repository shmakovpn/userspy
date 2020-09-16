"""
Tests for WMI exception class declared in wmi_exceptions.py

Author: shmakovpn <shmakovpn@yandex.ru>

Date: 2020-08-06
"""
from unittest import TestCase
import logging
# parent for all wmi exceptions
from wmi_exceptions.wmi_exception import WMIException


class TestWMIException(TestCase):
    """
    Testing WMI exception class
    """
    def test_wmi_exception_logger(self) -> None:
        """
        Tests that the logger declared in WMIException is **wmi** logger.
        """
        self.assertIsNotNone(getattr(WMIException, 'logger', None))
        self.assertEqual(WMIException.logger, logging.getLogger('wmi'))
