# pyp_reg_root_reg$net_bth$devices.py
#
# RegistryInfo module to analyze: Bluetooth devices.
#
# https://github.com/ufrisk/
#
# (c) Ulf Frisk, 2021
# Author: Ulf Frisk, pcileech@frizk.net
#

from memprocfs import RegUtil

print('MemProcFS Registry: Bluetooth Devices [ver: 2021-03-13] \n')

bthport_dict = {}
bthport_path = 'HKLM\\SYSTEM\\ControlSet001\\Services\\BTHPORT\\Parameters\\Devices'
print(bthport_path)

for dev_key in vmm.reg_key(bthport_path).subkeys():
    dev_path = bthport_path + '\\' + dev_key.name
    bthport_dict[dev_key.name.upper()] = [
        RegUtil.read_ascii(vmm, dev_path + '\\Name'),
        RegUtil.read_qword(vmm, dev_path + '\\LastConnected'),
        RegUtil.read_qword(vmm, dev_path + '\\LastSeen')
        ]

root_path = 'HKLM\\SYSTEM\\ControlSet001\\Enum\\BTHENUM'
print(root_path)

for vendor_key in vmm.reg_key(root_path).subkeys():
    if vendor_key.name[:4] != 'Dev_':
        continue
    vendor_path = root_path + '\\' + vendor_key.name
    RegUtil.print_keyvalue(2, vendor_key.name, vendor_key.time_str, 80, False, True)
    for dev_key in vmm.reg_key(vendor_path).subkeys():
        dev_path = vendor_path + '\\' + dev_key.name
        a = dev_path[-12:].upper()
        ah = "%s:%s:%s:%s:%s:%s" % (a[0:2], a[2:4], a[4:6], a[6:8], a[8:10], a[10:12])
        if a in bthport_dict:
            bthport = bthport_dict[a]
        else:
            bthport = {'', -1, -1}
        RegUtil.print_keyvalue(4, 'Address:        ' + a + ' / ' + ah, dev_key.time_str, 80, False, True)
        RegUtil.print_keyvalue(4, 'Device Name:    ' + RegUtil.read_utf16(vmm, dev_path + '\\FriendlyName'))
        RegUtil.print_keyvalue(4, 'First Insert:   ' + RegUtil.ft2str(RegUtil.read_qword(vmm, dev_path + '\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0065\\(Default)', True)))
        RegUtil.print_keyvalue(4, 'Last Insert:    ' + RegUtil.ft2str(RegUtil.read_qword(vmm, dev_path + '\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066\\(Default)', True)))
        RegUtil.print_keyvalue(4, 'Last Removal:   ' + RegUtil.ft2str(RegUtil.read_qword(vmm, dev_path + '\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0067\\(Default)', True)))
        RegUtil.print_keyvalue(4, 'BTHPORT Name:   ' + bthport[0])
        RegUtil.print_keyvalue(4, 'Last Connected: ' + RegUtil.ft2str(bthport[1]))
        RegUtil.print_keyvalue(4, 'Last Seen:      ' + RegUtil.ft2str(bthport[2]))
        print('    ---')
