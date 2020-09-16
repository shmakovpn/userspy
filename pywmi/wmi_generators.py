"""
WMI generators

Author: shmakovpn <shmakovpn@yandex.ru>

Date: 2020-08-11
"""
from typing import Iterator
from time import sleep
from collections import OrderedDict
from impacket.dcerpc.v5.dcom.wmi import IWbemClassObject
# settings
from wmi_settings import ADSettings, WMIConnectionSettings
# exceptions
from wmi_exceptions.wmi_connection_exceptions import WMIEnumNextUnknownException
# WMI context managers
from wmi_context_managers import wmi_connection, \
    wmi_interface, \
    wbem_level1_login, \
    wbem_services, \
    enum_wbem_class_object


def read_operation_count(wmi_connection_settings: WMIConnectionSettings, wmi_query_timeout) -> Iterator[int]

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
                                record: OrderedDict = pEnum.getProperties()
                                sum_read_operation_count += record["ReadOperationCount"]["value"]
                            except Exception as e:
                                if 'S_FALSE' not in str(e):
                                    raise WMIEnumNextUnknownException(e)
                                else:
                                    break
                        if last_sum_read_operation_count != sum_read_operation_count:
                            print(f'{last_sum_read_operation_count} {sum_read_operation_count}')
                        last_sum_read_operation_count = sum_read_operation_count
                        sleep(WMI_QUERY_TIMEOUT)  # sleep between wmi queries


cmds_allowed=ABOR,MKD,CWD,LIST,MDTM,NLST,PASS,PASV,PORT,PWD,QUIT,RETR,SIZE,STOR,TYPE,USER,ACCT,APPE,CDUP,HELP,MODE,NOOP,REIN,STAT,STRU,SYST,STOU
local_umask=0002
chown_upload_mode=0775
file_open_mode=0775
local_root=/mnt/store/store3/public/ВИКС

cmds_allowed=ABOR,MKD,CWD,DELE,LIST,MDTM,NLST,PASS,PASV,PORT,PWD,QUIT,RETR,RMD,RNFR,RNTO,SIZE,STOR,TYPE,USER,ACCT,APPE,CDUP,HELP,MODE,NOOP,REIN,STAT,STOU,STRU,SYST
local_umask=0002
chown_upload_mode=0775
file_open_mode=0775
local_root=/mnt/store/store2/public/ForAll/РОСПРОФЖЕЛ

