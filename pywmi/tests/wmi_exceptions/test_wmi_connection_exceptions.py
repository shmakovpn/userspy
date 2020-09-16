"""
Tests for WMI connection exceptions declared in wmi_exceptions.py

Author: shmakovpn <shmakovpn@yandex.ru>

Date: 2020-08-07
"""
# type hints
from typing import List, Tuple
# testing
from unittest import TestCase
from unittest.mock import MagicMock, patch
from unittest_dataprovider import data_provider
# wmi connection exceptions
from wmi_exceptions.wmi_connection_exceptions import WMIConnectionException, \
    WMIConnectionDCOMConnectionException, \
    WMIConnectionNoRouteToHostException, \
    WMIConnectionNetworkUnreachableException, \
    WMIConnectionNoAnswerException, \
    WMIConnectionRefusedException, \
    WMIConnectionDCOMConnectionUnknownException, \
    WMICoCreateInstanceException, \
    WMICoCreateInstanceAccessDeniedException, \
    WMICoCreateInstanceUnknownException, \
    WMICoCreateInstanceSocketTimeoutException, \
    WMIIWbemLevel1LoginException, \
    WMIIWbemLevel1LoginInitException, \
    WMIIWbemLevel1LoginInitUnknownException, \
    WMINTLMLoginException, \
    WMINTLMLoginNoAnswerException, \
    WMINTLMLoginTimeoutException, \
    WMINTLMLoginUnknownException, \
    WMIQueryException, \
    WMIQueryInvalidClassException, \
    WMIQueryInvalidQueryException, \
    WMIQueryUnknownException, \
    WMIEnumNextUnknownException
# settings
from wmi_settings import ADSettings, WMIConnectionSettings


class TestWMIConnectionExceptions(TestCase):
    """
    Testing WMI connection exceptions
    """
    def setUp(self) -> None:
        self.ad_settings = ADSettings(username='username', password='password', domain='domain')
        self.wmi_connection_settigns = WMIConnectionSettings(ad_settings=self.ad_settings, target='127.0.0.1')

    @patch('wmi_exceptions.wmi_exception.WMIException.__init__', return_value=None)
    @patch('wmi_exceptions.wmi_exception.WMIException.logger.warning')
    def test_wmi_connection_exception_init(self, logger_error_mock: MagicMock, init_mock: MagicMock) -> None:
        _ = WMIConnectionException(self.wmi_connection_settigns)
        init_mock.assert_called_once()
        init_mock.assert_called_once_with(
            f'WMIConnectionException. Unknown error! The message was not set!'
            f'. target={self.wmi_connection_settigns.target}'
        )
        logger_error_mock.assert_called_once()
        logger_error_mock.assert_called_once_with(
            'WMIConnectionException. Unknown error! The message was not set!'
            f'. target={self.wmi_connection_settigns.target}'
        )

    @staticmethod
    def exception_messages() -> List[Tuple[type, str]]:
        """
        Dataprovider for WMI connection exceptions messages
        """
        return [
            (WMIConnectionException, 'Unknown error! The message was not set!'),
            (WMIConnectionDCOMConnectionException, 'Unknown error! The message was not set!'),
            (WMIConnectionNoRouteToHostException, 'Could not connect: [Errno 113] No route to host'),
            (WMIConnectionNetworkUnreachableException, 'Could not connect: [Errno 101] Network is unreachable'),
            (WMIConnectionNoAnswerException, 'Could not connect: [WinError 10060] host answer timeout'),
            (WMIConnectionRefusedException, 'Could not connect: [Errno 111] Connection refused'),
            (WMIConnectionDCOMConnectionUnknownException, 'Could not connect: an unknown exception'),
            (WMICoCreateInstanceException, 'Unknown error! The message was not set!'),
            (WMICoCreateInstanceAccessDeniedException, 'CoCreateInstanceEx() failed. Access Denied'),
            (WMICoCreateInstanceUnknownException, 'CoCreateInstanceEx() failed: an unknown exception'),
            (WMICoCreateInstanceSocketTimeoutException, 'CoCreateInstanceEx() failed: socket timeout'),
            (WMIIWbemLevel1LoginException, 'Unknown error! The message was not set!'),
            (WMIIWbemLevel1LoginInitException, 'Unknown error! The message was not set!'),
            (
                WMIIWbemLevel1LoginInitUnknownException,
                'An unknown exception has occurred when IWbemLevel1Login.__init__'
            ),
            (WMINTLMLoginException, 'Unknown error! The message was not set!'),
            (WMINTLMLoginNoAnswerException, 'Could not connect: [WinError 10060] host answer timeout'),
            (WMINTLMLoginTimeoutException, 'Could not connect: [Errno 110] Connection timed out'),
            (WMINTLMLoginUnknownException, 'An unknown exception has occurred when IWbemLevel1Login.NTLMLogin()'),
            (WMIQueryException, 'Unknown error! The message was not set!'),
            (WMIQueryInvalidClassException, 'WMI query 0x80041010 - WBEM_E_INVALID_CLASS error'),
            (WMIQueryInvalidQueryException, 'WMI query 0x80041017 - WBEM_E_INVALID_QUERY error'),
            (WMIQueryUnknownException, 'WMI query unknown error'),
            (WMIEnumNextUnknownException, 'iEnumWbemClassObject.Next(0xffffffff, 1)[0] failed via unknown exception'),
        ]

    @data_provider(exception_messages)
    def test_wmi_connection_exception_message(self, wmi_exception_class: type, message: str) -> None:
        """
        Testing message member of WMI connection exception classes
        """
        self.assertEqual(wmi_exception_class.message, message)
