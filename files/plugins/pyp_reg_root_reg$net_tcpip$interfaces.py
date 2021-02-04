# pyp_reg_root_reg$net_interfaces.py
#
# RegistryInfo module to analyze: Network Interfaces.
#
# https://github.com/ufrisk/
#
# (c) Ulf Frisk, 2021
# Author: Ulf Frisk, pcileech@frizk.net
#

from vmmpy import *

print('MemProcFS Registry: Network Interfaces [ver: 2021-02-04] \n')

root_path = 'HKLM\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces'
print(root_path)

def print_values(path, values, off):
    value_names_time = ['LeaseObtainedTime', 'LeaseTerminatesTime', 'T1', 'T2']
    value_names_str = [
        'Domain', 'NameServer',  'DefaultGateway', 'IPAddress', 'SubnetMask',
        'DhcpIPAddress', 'DhcpSubnetMask', 'DhcpServer', 'DhcpDefaultGateway', 'DhcpNameServer', 'DhcpDomain', 'DhcpSubnetMaskOpt']
    if 'DhcpNetworkHint' in values:
        data_hex = regutil_read_utf16(values['DhcpNetworkHint']['data'])[::-1]
        data_str = bytes.fromhex(data_hex).decode('utf-8')[::-1]
        regutil_print_keyvalue(off, 'DhcpNetworkHint:', data_str, 50)
    if 'DhcpGatewayHardware' in values and values['DhcpGatewayHardware']['size'] >= 14:
        data_str = values['DhcpGatewayHardware']['data'][8:14].hex(':')
        regutil_print_keyvalue(off, 'DhcpGatewayHardware:', data_str, 50)
    for name in value_names_time:
        if name in values:
            time_unix = regutil_read_dword(values[name]['data'])
            if time_unix > 10000:
                time_ft = (11644473600 + time_unix) * 10000000
                regutil_print_filetime(off, name + ':', time_ft, 50)
    for name in value_names_str:
        if name in values and values[name]['size'] > 2:
            regutil_print_keyvalue(off, name + ':', regutil_read_utf16(values[name]['data']), 50)

for if_name, if_key in VmmPy_WinReg_KeyList(root_path)['subkeys'].items():
    if_path = root_path + '\\' + if_name
    if_keylist = VmmPy_WinReg_KeyList(if_path, True)
    regutil_print_keyvalue(2, if_name, if_key['time-str'], 80, False, True)
    print_values(if_path, if_keylist['values'], 4)
    for a_name, a_key in if_keylist['subkeys'].items():
        a_path = if_path + '\\' + a_name
        a_keylist = VmmPy_WinReg_KeyList(a_path, True)
        regutil_print_keyvalue(4, a_name, a_key['time-str'], 80, False, True)
        print_values(a_path, a_keylist['values'], 6)
