# pyp_reg_root_reg$tcpip_interfaces.py
#
# RegistryInfo module to analyze: Network Interfaces.
#
# https://github.com/ufrisk/
#
# (c) Ulf Frisk, 2021
# Author: Ulf Frisk, pcileech@frizk.net
#

from memprocfs import RegUtil

print('MemProcFS Registry: Network Interfaces [ver: 2021-03-13] \n')

root_path = 'HKLM\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces'
print(root_path)

def print_values(path, values, off):
    value_names_time = ['LeaseObtainedTime', 'LeaseTerminatesTime', 'T1', 'T2']
    value_names_str = [
        'Domain', 'NameServer',  'DefaultGateway', 'IPAddress', 'SubnetMask',
        'DhcpIPAddress', 'DhcpSubnetMask', 'DhcpServer', 'DhcpDefaultGateway', 'DhcpNameServer', 'DhcpDomain', 'DhcpSubnetMaskOpt']
    if 'DhcpNetworkHint' in values:
        data_hex = RegUtil.read_utf16(vmm, values['DhcpNetworkHint'].value)[::-1]
        data_str = bytes.fromhex(data_hex).decode('utf-8')[::-1]
        RegUtil.print_keyvalue(off, 'DhcpNetworkHint:', data_str, 50)
    if 'DhcpGatewayHardware' in values and values['DhcpGatewayHardware'].size >= 14:
        data_str = values['DhcpGatewayHardware'].value[8:14].hex(':')
        RegUtil.print_keyvalue(off, 'DhcpGatewayHardware:', data_str, 50)
    for name in value_names_time:
        if name in values:
            time_unix = RegUtil.read_dword(vmm, values[name].value)
            if time_unix > 10000:
                time_ft = (11644473600 + time_unix) * 10000000
                RegUtil.print_filetime(off, name + ':', time_ft, 50)
    for name in value_names_str:
        if name in values and values[name].size > 2:
            RegUtil.print_keyvalue(off, name + ':', RegUtil.read_utf16(vmm, values[name].value), 50)

for if_key in vmm.reg_key(root_path).subkeys():
    if_path = root_path + '\\' + if_key.name
    RegUtil.print_keyvalue(2, if_key.name, if_key.time_str, 80, False, True)
    print_values(if_path, if_key.values_dict(), 4)
    for a_key in if_key.subkeys():
        a_path = if_path + '\\' + a_key.name
        RegUtil.print_keyvalue(4, a_key.name, a_key.time_str, 80, False, True)
        print_values(a_path, a_key.values_dict(), 6)
