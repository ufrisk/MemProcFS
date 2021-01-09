# pyp_reg_root_reg$usb_usb$devices.py
#
# RegistryInfo module to analyze: USB devices.
#
# https://github.com/ufrisk/
#
# (c) Ulf Frisk, 2021
# Author: Ulf Frisk, pcileech@frizk.net
#

from vmmpy import *

print('MemProcFS Registry: USB Devices [2021-01-09] \n')

root_path = 'HKLM\\SYSTEM\\ControlSet001\\Enum\\USB'
print(root_path)

for vendor_name, vendor_key in VmmPy_WinReg_KeyList(root_path)['subkeys'].items():
    vendor_path = root_path + '\\' + vendor_name
    regutil_print_keyvalue(2, vendor_key['name'], vendor_key['time-str'], 80, False, True)
    for dev_name, dev_key in VmmPy_WinReg_KeyList(vendor_path)['subkeys'].items():
        dev_path = vendor_path + '\\' + dev_name
        regutil_print_keyvalue(4, 'Serial Number:   ' + dev_key['name'], dev_key['time-str'], 80, False, True)
        regutil_print_keyvalue(6, 'Device Name:   ' + regutil_read_utf16(dev_path + '\\Properties\\{a8b865dd-2e3d-4094-ad97-e593a70c75d6}\\0004\\(Default)', True))
        regutil_print_keyvalue(6, 'First Insert:  ' + regutil_ft2str(regutil_read_qword(dev_path    + '\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0065\\(Default)', True)))
        regutil_print_keyvalue(6, 'Last Insert:   ' + regutil_ft2str(regutil_read_qword(dev_path    + '\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066\\(Default)', True)))
        regutil_print_keyvalue(6, 'Last Removal:  ' + regutil_ft2str(regutil_read_qword(dev_path    + '\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0067\\(Default)', True)))
        print('    ---')
