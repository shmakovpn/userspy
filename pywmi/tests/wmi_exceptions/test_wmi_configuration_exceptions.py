"""
Tests for WMI configuration exceptions classes declared in wmi_exceptions.py

Author: shmakovpn <shmakovpn@yandex.ru>

Date: 2020-08-06
"""
# type hints
from typing import List, Tuple
# tests
from unittest import TestCase
from unittest.mock import MagicMock, patch
from unittest_dataprovider import data_provider
# wmi configuration exceptions
from wmi_exceptions.wmi_configuration_exceptions import WMIConfigurationException, \
    WMIConfigurationUsernameException, \
    WMIConfigurationPasswordException, \
    WMIConfigurationDomainException, \
    WMIConfigurationAddressException


class TestWMIConfigurationExceptions(TestCase):
    """
    Testing WMI configuration exceptions
    """
    @patch('wmi_exceptions.wmi_exception.WMIException.__init__', return_value=None)
    @patch('wmi_exceptions.wmi_exception.WMIException.logger.error')
    def test_wmi_configuration_exception_init(self, logger_error_mock: MagicMock, init_mock: MagicMock) -> None:
        _ = WMIConfigurationException()
        init_mock.assert_called_once()
        init_mock.assert_called_once_with(
            'WMIConfigurationException. Unknown error! The message was not set!. '
            'Please create needed environment and try again.'
        )
        logger_error_mock.assert_called_once()
        logger_error_mock.assert_called_once_with('WMIConfigurationException. Unknown error! The message was not set!')

    @staticmethod
    def exception_messages() -> List[Tuple[type, str]]:
        """
        Dataprovider for WMI configuration exceptions messages
        """
        return [
            (WMIConfigurationException, 'Unknown error! The message was not set!'),
            (WMIConfigurationUsernameException, 'An environment variable AD_USERNAME does not exist'),
            (WMIConfigurationPasswordException, 'An environment variable AD_PASSWORD does not exist'),
            (WMIConfigurationDomainException, 'An environment variable AD_DOMAIN does not exist'),
            (WMIConfigurationAddressException, 'An environment variable WMI_ADDRESS does not exist'),
        ]

    @data_provider(exception_messages)
    def test_wmi_configuration_exception_message(self, wmi_exception_class: type, message: str) -> None:
        """
        Testing message member of WMI configuration exception classes
        """
        self.assertEqual(wmi_exception_class.message, message)

    @data_provider(exception_messages)
    # path to disable logging
    @patch('wmi_exceptions.wmi_configuration_exceptions.WMIConfigurationException.__init__', return_value=None)
    def test_wmi_configuration_exception_get_log_message(
            self, wmi_exception_class: type, message: str, init_mock: MagicMock
    ) -> None:
        e: wmi_exception_class = wmi_exception_class()
        init_mock.assert_called_once()
        init_mock.assert_called_once_with()  # assert called without any arguments
        self.assertEqual(
            e._get_log_message(),
            f'{wmi_exception_class.__name__}. {message}'
        )

    @data_provider(exception_messages)
    @patch('wmi_exceptions.wmi_exception.WMIException.logger.error')
    def test_wmi_configuration_exception_logging(
            self,
            wmi_exception_class: type,
            message: str,
            logger_error_mock: MagicMock,
    ) -> None:
        _ = wmi_exception_class()
        logger_error_mock.assert_called_once()
        logger_error_mock.assert_called_once_with(f'{wmi_exception_class.__name__}. {message}')
