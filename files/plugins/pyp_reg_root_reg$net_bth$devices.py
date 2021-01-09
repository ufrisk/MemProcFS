# pyp_reg_root_reg$net_bth$devices.py
#
# RegistryInfo module to analyze: Bluetooth devices.
#
# https://github.com/ufrisk/
#
# (c) Ulf Frisk, 2021
# Author: Ulf Frisk, pcileech@frizk.net
#

from vmmpy import *

print('MemProcFS Registry: Bluetooth Devices [2021-01-09] \n')

bthport_dict = {}
bthport_path = 'HKLM\\SYSTEM\\ControlSet001\\Services\\BTHPORT\\Parameters\\Devices'
print(bthport_path)

for dev_name in VmmPy_WinReg_KeyList(bthport_path)['subkeys']:
    dev_path = bthport_path + '\\' + dev_name
    bthport_dict[dev_name.upper()] = [
        regutil_read_ascii(dev_path + '\\Name'),
        regutil_read_qword(dev_path + '\\LastConnected'),
        regutil_read_qword(dev_path + '\\LastSeen')
        ]

root_path = 'HKLM\\SYSTEM\\ControlSet001\\Enum\\BTHENUM'
print(root_path)

for vendor_name, vendor_key in VmmPy_WinReg_KeyList(root_path)['subkeys'].items():
    if vendor_name[:4] != 'Dev_':
        continue
    vendor_path = root_path + '\\' + vendor_name
    regutil_print_keyvalue(2, vendor_name, vendor_key['time-str'], 80, False, True)
    for dev_name, dev_key in VmmPy_WinReg_KeyList(vendor_path)['subkeys'].items():
        dev_path = vendor_path + '\\' + dev_name
        a = dev_path[-12:].upper()
        ah = "%s:%s:%s:%s:%s:%s" % (a[0:2], a[2:4], a[4:6], a[6:8], a[8:10], a[10:12])
        if a in bthport_dict:
            bthport = bthport_dict[a]
        else:
            bthport = {'', -1, -1}
        regutil_print_keyvalue(4, 'Address:        ' + a + ' / ' + ah, dev_key['time-str'], 80, False, True)
        regutil_print_keyvalue(4, 'Device Name:    ' + regutil_read_utf16(dev_path + '\\FriendlyName'))
        regutil_print_keyvalue(4, 'First Insert:   ' + regutil_ft2str(regutil_read_qword(dev_path    + '\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0065\\(Default)', True)))
        regutil_print_keyvalue(4, 'Last Insert:    ' + regutil_ft2str(regutil_read_qword(dev_path    + '\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066\\(Default)', True)))
        regutil_print_keyvalue(4, 'Last Removal:   ' + regutil_ft2str(regutil_read_qword(dev_path    + '\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0067\\(Default)', True)))
        regutil_print_keyvalue(4, 'BTHPORT Name:   ' + bthport[0])
        regutil_print_keyvalue(4, 'Last Connected: ' + regutil_ft2str(bthport[1]))
        regutil_print_keyvalue(4, 'Last Seen:      ' + regutil_ft2str(bthport[2]))
        print('    ---')
