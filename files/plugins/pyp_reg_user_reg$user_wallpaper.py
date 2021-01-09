# pyp_reg_user_reg$user_wallpaper.py
#
# RegistryInfo module to analyze: User Desktop Wallpapers.
#
# https://github.com/ufrisk/
#
# (c) Ulf Frisk, 2021
# Author: Ulf Frisk, pcileech@frizk.net
#

from vmmpy import *

print('MemProcFS Registry: User Desktop Wallpapers [2021-01-09] \n')

# NB! string 'path' and object 'user' are guaranteed to exist in user lignt plugins.
root_path = 'HKU\\' + user['name'] + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Wallpaper\\MRU'
print(root_path)

reg_wp = VmmPy_WinReg_KeyList(root_path, True)['values']
mrulist = regutil_mrulistex_expand(reg_wp['MRUListEx']['data'])
print('MRU#   Path')
print('===========')
for mru in mrulist:
    data = reg_wp[str(mru)]['data']
    data_end = data.index(b'\x00\x00')
    if data_end != -1:
        if data_end % 2 == 1:
            data_end = data_end + 1
        data = data[0:data_end]
    print("%4i   %s" % (mru, data.decode('utf-16le')))
