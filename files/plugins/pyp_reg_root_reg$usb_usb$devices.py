# pyp_reg_root_reg$usb_usb$devices.py
#
# RegistryInfo module to analyze: USB devices.
#
# https://github.com/ufrisk/
#
# (c) Ulf Frisk, 2021
# Author: Ulf Frisk, pcileech@frizk.net
#

from memprocfs import RegUtil

print('MemProcFS Registry: USB Devices [ver: 2021-03-13] \n')

root_path = 'HKLM\\SYSTEM\\ControlSet001\\Enum\\USB'
print(root_path)

for vendor_key in vmm.reg_key(root_path).subkeys():
    vendor_path = root_path + '\\' + vendor_key.name
    RegUtil.print_keyvalue(2, vendor_key.name, vendor_key.time_str, 80, False, True)
    for dev_key in vmm.reg_key(vendor_path).subkeys():
        dev_path = vendor_path + '\\' + dev_key.name
        RegUtil.print_keyvalue(4, 'Serial Number:   ' + dev_key.name, dev_key.time_str, 80, False, True)
        RegUtil.print_keyvalue(6, 'Device Name:   ' + RegUtil.read_utf16(vmm, dev_path + '\\Properties\\{a8b865dd-2e3d-4094-ad97-e593a70c75d6}\\0004\\(Default)', True))
        RegUtil.print_keyvalue(6, 'First Insert:  ' + RegUtil.ft2str(RegUtil.read_qword(vmm, dev_path + '\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0065\\(Default)', True)))
        RegUtil.print_keyvalue(6, 'Last Insert:   ' + RegUtil.ft2str(RegUtil.read_qword(vmm, dev_path + '\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066\\(Default)', True)))
        RegUtil.print_keyvalue(6, 'Last Removal:  ' + RegUtil.ft2str(RegUtil.read_qword(vmm, dev_path + '\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0067\\(Default)', True)))
        print('    ---')
