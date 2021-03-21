# pyp_reg_user_reg$user_wallpaper.py
#
# RegistryInfo module to analyze: User Desktop Wallpapers.
#
# https://github.com/ufrisk/
#
# (c) Ulf Frisk, 2021
# Author: Ulf Frisk, pcileech@frizk.net
#

import memprocfs

print('MemProcFS Registry: User Desktop Wallpapers [ver: 2021-03-13] \n')

# NB! string 'path' and objects 'vmm' and 'user' are guaranteed to exist in user light plugins.
root_path = 'HKU\\' + user['name'] + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Wallpaper\\MRU'
print(root_path)

reg_wp = vmm.reg_key(root_path).values_dict()
mrulist = memprocfs.RegUtil.mrulistex_expand(reg_wp['MRUListEx'].value)

print('MRU#   Path')
print('===========')
for mru in mrulist:
    print("%4i   %s" % (mru, reg_wp[str(mru)].vstr(False)))
