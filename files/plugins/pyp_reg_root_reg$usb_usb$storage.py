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

from memprocfs import RegUtil

print('MemProcFS Registry: USB Storage [ver: 2021-03-13] \n')

root_path = 'HKLM\\SYSTEM\\ControlSet001\\Enum\\USBSTOR'
print(root_path)

for vendor_key in vmm.reg_key(root_path).subkeys():
    vendor_path = root_path + '\\' + vendor_key.name
    vendor_name = vendor_key.name.replace('Disk&Ven_', 'Vendor=').replace('&Prod_', ', Product=').replace('&Rev_', ', Rev=')
    RegUtil.print_keyvalue(2, vendor_name, vendor_key.time_str, 80, False, True)
    for dev_key in vmm.reg_key(vendor_path).subkeys():
        dev_path = vendor_path + '\\' + dev_key.name
        props_path = dev_path + '\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}'
        RegUtil.print_keyvalue(4, 'Serial Number:   ' + dev_key.name, dev_key.time_str, 80, False, True)
        vidpid = RegUtil.read_utf16(vmm, props_path + '\\000A\\(Default)', True)
        vidpid = vidpid.replace('USB\VID_', 'VID=').replace('&PID_', ', PID=').replace('\\', ', SN=')
        RegUtil.print_keyvalue(6, 'Device IDs:    ' + vidpid)
        RegUtil.print_keyvalue(6, 'Device Name:   ' + RegUtil.read_utf16(vmm, dev_path + '\\FriendlyName'))
        RegUtil.print_keyvalue(6, 'First Insert:  ' + RegUtil.ft2str(RegUtil.read_qword(vmm, props_path + '\\0065\\(Default)', True)))
        RegUtil.print_keyvalue(6, 'Last Insert:   ' + RegUtil.ft2str(RegUtil.read_qword(vmm, props_path + '\\0066\\(Default)', True)))
        RegUtil.print_keyvalue(6, 'Last Removal:  ' + RegUtil.ft2str(RegUtil.read_qword(vmm, props_path + '\\0067\\(Default)', True)))
        print('    ---')
