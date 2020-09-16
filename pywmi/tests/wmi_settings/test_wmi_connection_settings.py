# type hints
from typing import Any, Dict
# testing
from unittest import TestCase
from unittest.mock import MagicMock, patch
# wmi configuration exceptions
from wmi_exceptions.wmi_configuration_exceptions import WMIConfigurationException, WMIConfigurationAddressException
#
from wmi_settings import ADSettings, WMIConnectionSettings


class TestWMIConnectionSettings(TestCase):
    """
    Testing WMIConnectionSettings class
    """
    def setUp(self) -> None:
        self.ad_settings: ADSettings = ADSettings(
            username='username',
            password='password',
            domain='domain'
        )
        self.wmi_connection_settings: WMIConnectionSettings = WMIConnectionSettings(
            target='127.0.0.1',
            ad_settings=self.ad_settings
        )

    def test_wmi_connection_settings_init(self) -> None:
        self.assertEqual(self.wmi_connection_settings.target, '127.0.0.1')
        self.assertEqual(self.wmi_connection_settings.ad_settings, self.ad_settings)

    def test_wmi_connection_settings_str(self) -> None:
        self.assertEqual(
            str(self.wmi_connection_settings),
            f'WMIConnectionSettings(ad_settings={str(self.ad_settings)}, target="127.0.0.1")'
        )

    def test_wmi_connection_settings_repr(self) -> None:
        self.assertEqual(
            repr(self.wmi_connection_settings),
            f'WMIConnectionSettings(ad_settings={repr(self.ad_settings)}, target="127.0.0.1")'
        )

    @patch('os.environ.get', return_value=None)
    @patch('wmi_exceptions.wmi_configuration_exceptions.WMIConfigurationException.__init__', return_value=None)
    def test_wmi_connection_settings_init_no_environ(
            self,
            wmi_exception_init_mock: MagicMock,
            environ_get_mock: MagicMock
    ) -> None:
        try:
            # creating an instance of WMIConnectionSettings with address=None (using default argument value)
            _ = WMIConnectionSettings(ad_settings=self.ad_settings)
        except WMIConfigurationException as e:
            self.assertEqual(type(e), WMIConfigurationAddressException)
        environ_get_mock.assert_called_once()
        environ_get_mock.assert_called_once_with('WMI_ADDRESS')
        wmi_exception_init_mock.assert_called_once()
        wmi_exception_init_mock.assert_called_once_with()

    @patch('os.environ.get', return_value='127.0.0.1')
    @patch('wmi_exceptions.wmi_configuration_exceptions.WMIConfigurationException.__init__', return_value=None)
    def test_wmi_connection_settings_init_with_environ(
            self,
            wmi_exception_init_mock: MagicMock,
            environ_get_mock: MagicMock
    ) -> None:
        # creating an instance of WMIConnectionSettings with address=None (using default argument value)
        wmi_connection_settings: WMIConnectionSettings = WMIConnectionSettings(ad_settings=self.ad_settings)
        environ_get_mock.assert_called_once()
        environ_get_mock.assert_called_once_with('WMI_ADDRESS')
        wmi_exception_init_mock.assert_not_called()
        self.assertEqual(wmi_connection_settings.target, '127.0.0.1')

    def test_wmi_connection_settings_kwargs(self):
        wmi_connection_settings: WMIConnectionSettings = WMIConnectionSettings(
            ad_settings=self.ad_settings,
            target='127.0.0.1'
        )
        kwargs: Dict[str, Any] = wmi_connection_settings.kwargs()
        self.assertIn('ad_settings', kwargs)
        self.assertEqual(kwargs.pop('ad_settings'), self.ad_settings)
        self.assertIn('target', kwargs)
        self.assertEqual(kwargs.pop('target'), '127.0.0.1')
        self.assertIn('aesKey', kwargs)
        self.assertEqual(kwargs.pop('aesKey'), None)
        self.assertIn('doKerberos', kwargs)
        self.assertEqual(kwargs.pop('doKerberos'), False)
        self.assertIn('kdcHost', kwargs)
        self.assertEqual(kwargs.pop('kdcHost'), None)
        self.assertIn('lmhash', kwargs)
        self.assertEqual(kwargs.pop('lmhash'), '')
        self.assertIn('nthash', kwargs)
        self.assertEqual(kwargs.pop('nthash'), '')
        self.assertIn('oxidResolver', kwargs)
        self.assertEqual(kwargs.pop('oxidResolver'), True)
        self.assertEqual(len(kwargs), 0)

    def test_get_connection_settings_kwargs(self):
        wmi_connection_settings: WMIConnectionSettings = WMIConnectionSettings(
            ad_settings=self.ad_settings,
            target='127.0.0.1'
        )
        kwargs: Dict[str, Any] = wmi_connection_settings.get_connection_settings_kwargs()
        self.assertIn('username', kwargs)
        self.assertEqual(kwargs.pop('username'), 'username')
        self.assertIn('password', kwargs)
        self.assertEqual(kwargs.pop('password'), 'password')
        self.assertIn('domain', kwargs)
        self.assertEqual(kwargs.pop('domain'), 'domain')
        self.assertIn('target', kwargs)
        self.assertEqual(kwargs.pop('target'), '127.0.0.1')
        self.assertIn('aesKey', kwargs)
        self.assertEqual(kwargs.pop('aesKey'), None)
        self.assertIn('doKerberos', kwargs)
        self.assertEqual(kwargs.pop('doKerberos'), False)
        self.assertIn('kdcHost', kwargs)
        self.assertEqual(kwargs.pop('kdcHost'), None)
        self.assertIn('lmhash', kwargs)
        self.assertEqual(kwargs.pop('lmhash'), '')
        self.assertIn('nthash', kwargs)
        self.assertEqual(kwargs.pop('nthash'), '')
        self.assertIn('oxidResolver', kwargs)
        self.assertEqual(kwargs.pop('oxidResolver'), True)
        self.assertEqual(len(kwargs), 0)
