# memprocfs_pythonexec_example.py
#
# MemProcFS supports running a Python program at start-up in the context of the
# plugin sub-system with full access to the MemProcFS Python API. For more info
# about the API - please check out the guide at:
# https://github.com/ufrisk/MemProcFS/wiki/API_Python
#
# MemProcFS plugins and start-up programs are supported on Windows and Linux.
#
# Example:
# memprocfs.exe -device memory.dmp -pythonexec memprocfs_pythonexec_example.py
#
# This example will display a process list, search for RWX-sections in memory
# and (if forensic mode is enabled) copy the CSV files to C:\Temp\.
#
# Note how the vmm MemProcFS API object is already pre-existing ready for use.
#
# Also note how it's a good idea to surround your program with a try-except.
#
# https://github.com/ufrisk/MemProcFS
#
# (c) Ulf Frisk, 2022
# Author: Ulf Frisk, pcileech@frizk.net
#



print("--------------- START MEMPROCFS PYTHONEXEC EXAMPLE ---------------")


try:
    print("")
    print("1. Processes by pid/name:")
    print("-------------------------")
    for process in vmm.process_list():
        print("%i: \t %s" % (process.pid, process.fullname))
except Exception as e:
    print("memprocfs_pythonexec_example.py: exception: " + str(e))


try:
    print("")
    print("2. RWX memory [max 5 per process]")
    print("---------------------------------")
    for process in vmm.process_list():
        crwx = 0
        for entry in process.maps.pte():
            if '-rwx' in entry['flags']:
                print("%i: \t %s \t %s" % (process.pid, process.name, str(entry)))
                crwx += 1
                if crwx >= 5: break
except Exception as e:
    print("memprocfs_pythonexec_example.py: exception: " + str(e))


try:
    print("")
    print("3. Copy CSV files from forensic mode (if enabled)")
    print("-------------------------------------------------")
    import os
    dst_path_base = '/tmp/' if os.sep == '/' else 'C:\\Temp\\'
    vfs_files = vmm.vfs.list("/forensic/csv/")
    for vfs_file in vfs_files:
        if not vfs_files[vfs_file]['f_isdir']:
            offset = 0
            vfs_path = "/forensic/csv/" + vfs_file
            dst_path = dst_path_base + 'memprocfs_pythonexec_example_' + vfs_file
            print("copy file '%s' to '%s'" % (vfs_path, dst_path))
            with open(dst_path, "wb") as file:
                while offset < vfs_files[vfs_file]['size']:
                    chunk = vmm.vfs.read(vfs_path, 0x00100000, offset)
                    offset += len(chunk)
                    file.write(chunk)
except Exception as e:
    print("memprocfs_pythonexec_example.py: exception: " + str(e))


print("---------------- END MEMPROCFS PYTHONEXEC EXAMPLE ----------------")
