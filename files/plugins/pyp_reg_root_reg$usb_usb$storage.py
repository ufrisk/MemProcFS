# pyp_reg_root_reg$usb_usb$storage.py
#
# RegistryInfo module to analyze: USB storage devices.
# https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10
#
# https://github.com/ufrisk/
#
# (c) Ulf Frisk, 2021
# Author: Ulf Frisk, pcileech@frizk.net
#

from vmmpy import *

print('MemProcFS Registry: USB Storage [ver: 2021-01-09] \n')

root_path = 'HKLM\\SYSTEM\\ControlSet001\\Enum\\USBSTOR'
print(root_path)

for vendor_name, vendor_key in VmmPy_WinReg_KeyList(root_path)['subkeys'].items():
    vendor_path = root_path + '\\' + vendor_name
    vendor_name = vendor_name.replace('Disk&Ven_', 'Vendor=').replace('&Prod_', ', Product=').replace('&Rev_', ', Rev=')
    regutil_print_keyvalue(2, vendor_name, vendor_key['time-str'], 80, False, True)
    for dev_name, dev_key in VmmPy_WinReg_KeyList(vendor_path)['subkeys'].items():
        dev_path = vendor_path + '\\' + dev_name
        props_path = dev_path + '\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}'
        regutil_print_keyvalue(4, 'Serial Number:   ' + dev_key['name'], dev_key['time-str'], 80, False, True)
        vidpid = regutil_read_utf16(props_path + '\\000A\\(Default)', True)
        vidpid = vidpid.replace('USB\VID_', 'VID=').replace('&PID_', ', PID=').replace('\\', ', SN=')
        regutil_print_keyvalue(6, 'Device IDs:    ' + vidpid)
        regutil_print_keyvalue(6, 'Device Name:   ' + regutil_read_utf16(dev_path + '\\FriendlyName'))
        regutil_print_keyvalue(6, 'First Insert:  ' + regutil_ft2str(regutil_read_qword(props_path + '\\0065\\(Default)', True)))
        regutil_print_keyvalue(6, 'Last Insert:   ' + regutil_ft2str(regutil_read_qword(props_path + '\\0066\\(Default)', True)))
        regutil_print_keyvalue(6, 'Last Removal:  ' + regutil_ft2str(regutil_read_qword(props_path + '\\0067\\(Default)', True)))
        print('    ---')
