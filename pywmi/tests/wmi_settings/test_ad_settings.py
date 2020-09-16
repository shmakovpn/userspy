"""
Tests for class ADSettings from wmi_settings.py

Author: shmakovpn <shmakovpn@yandex.ru>

Date: 2020-08-06
"""
# type hints
from typing import Optional, Tuple, List
# testing
from unittest import TestCase
from unittest.mock import patch, MagicMock, call
from unittest_dataprovider import data_provider
# wmi configuration exceptions
from wmi_exceptions.wmi_configuration_exceptions import WMIConfigurationException, \
    WMIConfigurationUsernameException, \
    WMIConfigurationPasswordException, \
    WMIConfigurationDomainException
#
from wmi_settings import ADSettings


class TestADSettings(TestCase):
    """
    Testing ADSettings class
    """
    @staticmethod
    def settings_combinations() -> List[Tuple[Tuple[str, str, str], type]]:
        """
        ADSettings combinations
        :return:
        """
        return [
            ((None, 'password', 'domain'), WMIConfigurationUsernameException),
            (('username', None, 'domain'), WMIConfigurationPasswordException),
            (('username', 'password', None), WMIConfigurationDomainException),
            ((None, None, None), WMIConfigurationUsernameException),
            (('username', None, None), WMIConfigurationPasswordException),
            (('username', 'password', 'domain'), None),
        ]

    @data_provider(settings_combinations)
    @patch('os.environ.get', return_value=None)
    @patch('wmi_exceptions.wmi_configuration_exceptions.WMIConfigurationException.__init__', return_value=None)
    def test_ad_settings_init_no_environment(
            self,
            args: Tuple[Optional[str], Optional[str], Optional[str]],
            wmi_exception_class: Optional[type],
            wmi_exception_init_mock: MagicMock,
            environ_get_mock: MagicMock
    ) -> None:
        """
        Testing ADSettings __init__ with different combinations of arguments
        """
        try:
            _ = ADSettings(
                username=args[0],
                password=args[1],
                domain=args[2]
            )
        except WMIConfigurationException as e:  # catch all types of WMI exceptions
            self.assertEqual(e.__class__, wmi_exception_class)
            # if any of arguments of __init__ of ADSettings is None, os.environ.get have to be called
            environ_get_mock.assert_called_once()
            # if any of arguments of __init__ of ADSettings is None, WMIException have to be created
            wmi_exception_init_mock.assert_called_once()
        else:
            # if all of arguments of __init__ of ADSettings is not None, os.environ.get have not to be called
            environ_get_mock.assert_not_called()
            # if all of arguments of __init__ of ADSettings is not None, WMIException have not to be created
            wmi_exception_init_mock.assert_not_called()

    @patch('os.environ.get', side_effect=lambda name: name)
    @patch('wmi_exceptions.wmi_configuration_exceptions.WMIConfigurationException.__init__', return_value=None)
    def test_ad_settings_init_with_environment(
            self,
            wmi_exception_init_mock: MagicMock,
            environ_get_mock: MagicMock
    ) -> None:
        """
        Testing ADSettings __init__ with all of argument are set to None and all needed environment variables are set
        """
        ad_settings: ADSettings = ADSettings()
        wmi_exception_init_mock.assert_not_called()
        self.assertEqual(environ_get_mock.call_count, 3)
        self.assertEqual(environ_get_mock.mock_calls[0], call('AD_USERNAME'))
        self.assertEqual(environ_get_mock.mock_calls[1], call('AD_PASSWORD'))
        self.assertEqual(environ_get_mock.mock_calls[2], call('AD_DOMAIN'))
        self.assertEqual(ad_settings.username, 'AD_USERNAME')
        self.assertEqual(ad_settings.password, 'AD_PASSWORD')
        self.assertEqual(ad_settings.domain, 'AD_DOMAIN')

    def test_ad_settings_str(self):
        self.assertEqual(
            str(ADSettings('username', 'password', 'domain')),
            f'ADSettings(ad_username="username", ad_password="password", ad_domain="domain")'
        )

    def test_ad_settings_repr(self):
        ad_settings: ADSettings = ADSettings('username', 'password', 'domain')
        self.assertEqual(str(ad_settings), repr(ad_settings))

    def test_ad_settings_kwargs(self):
        ad_settings: ADSettings = ADSettings('username', 'password', 'domain')
        self.assertEqual(
            ad_settings.kwargs(),
            {'domain': 'domain', 'password': 'password', 'username': 'username'},
        )
