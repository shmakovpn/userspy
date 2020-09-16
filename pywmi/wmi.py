"""
This script performs WMI requests to PCs under Windows for retrieving a value of the interrupts counter

Author: shmakovpn

2020-07-28
"""
# from typing import Optional, ContextManager
# from contextlib import contextmanager
# import socket
from time import sleep
from collections import OrderedDict
# impacket
# from impacket.dcerpc.v5.dtypes import NULL
# from impacket.dcerpc.v5.dcom import wmi
# from impacket.dcerpc.v5.dcom.wmi import IWbemLevel1Login, \
#     IWbemServices, \
#     IEnumWbemClassObject, \
#     DCERPCSessionError, \
#     IWbemClassObject
# from impacket.dcerpc.v5.dcomrt import DCOMConnection, IRemUnknown2
# from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.dcom.wmi import IWbemClassObject
# settings
from wmi_settings import ADSettings, WMIConnectionSettings
# exceptions
from wmi_exceptions.wmi_connection_exceptions import WMIEnumNextUnknownException
# from wmi_exceptions.wmi_connection_exceptions import WMIConnectionNoRouteToHostException, \
#     WMIConnectionNetworkUnreachableException, \
#     WMIConnectionNoAnswerException, \
#     WMIConnectionRefusedException, \
#     WMIConnectionDCOMConnectionUnknownException, \
#     WMICoCreateInstanceAccessDeniedException, \
#     WMICoCreateInstanceUnknownException, \
#     WMICoCreateInstanceSocketTimeoutException, \
#     WMIIWbemLevel1LoginInitUnknownException, \
#     WMINTLMLoginNoAnswerException, \
#     WMINTLMLoginTimeoutException, \
#     WMINTLMLoginUnknownException, \
#     WMIQueryInvalidClassException, \
#     WMIQueryInvalidQueryException, \
#     WMIQueryUnknownException, \
#     WMIEnumNextUnknownException
# WMI context managers
from wmi_context_managers import wmi_connection, \
    wmi_interface, \
    wbem_level1_login, \
    wbem_services, \
    enum_wbem_class_object

WMI_QUERY_TIMEOUT: int = 1  #: timeout between wmi queries


def main() -> None:
    """
    This program starts here
    """
    # creating ad_settings instance providing authentication using environment variables
    ad_settings: ADSettings = ADSettings()
    # creating wmi connection settings providing authentication using environment variables
    wmi_connection_settings: WMIConnectionSettings = WMIConnectionSettings(ad_settings=ad_settings)

    with wmi_connection(wmi_connection_settings) as dcom_connection:
        with wmi_interface(dcom_connection, wmi_connection_settings) as iInterface:
            with wbem_level1_login(iInterface, wmi_connection_settings) as iWbemLevel1Login:
                with wbem_services(iWbemLevel1Login, wmi_connection_settings) as iWbemServices:
                    wmi_query_string: str = 'SELECT ReadOperationCount FROM Win32_process where name="csrss.exe"'
                    last_sum_read_operation_count: int = 0
                    while True:
                        with enum_wbem_class_object(iWbemServices, wmi_query_string) as iEnumWbemClassObject:
                            sum_read_operation_count: int = 0  # sum of read operation count for all sessions
                            while True:
                                try:
                                    pEnum: IWbemClassObject = iEnumWbemClassObject.Next(0xffffffff, 1)[0]
                                except Exception as e:
                                    if 'S_FALSE' not in str(e):
                                        raise WMIEnumNextUnknownException(e)
                                    else:
                                        break
                                record: OrderedDict = pEnum.getProperties()
                                sum_read_operation_count += record["ReadOperationCount"]["value"]
                            if last_sum_read_operation_count != sum_read_operation_count:
                                print(f'{last_sum_read_operation_count} {sum_read_operation_count}')
                            last_sum_read_operation_count = sum_read_operation_count
                            sleep(WMI_QUERY_TIMEOUT)  # sleep between wmi queries


if __name__ == '__main__':
    main()
    print(f"END")
