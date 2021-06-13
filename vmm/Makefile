#
# NOTE! PACKAGE DEPENDENCY ON LeechCore:
#       The build script require leechcore.so built from the leechcore project
#       which is found at https://github.com/ufrisk/LeechCore to build. This
#       file is assumed to exist in either of the directories: 
#       . (current), ../files, ../../LeechCore*/files
#
CC=gcc
CFLAGS  += -std=c11 -I. -I../includes -D LINUX -D _GNU_SOURCE -D SQLITE_THREADSAFE=2 -shared -fPIC -l:leechcore.so -fvisibility=hidden -L. -lm -pthread `pkg-config liblz4 openssl --libs --cflags`
#CFLAGS  += -g -O0
CFLAGS  += -fPIE -pie -fstack-protector -D_FORTIFY_SOURCE=2 -O1 -Wl,-z,noexecstack
CFLAGS  += -Wall -Wno-format-truncation -Wno-enum-compare -Wno-pointer-sign -Wno-multichar -Wno-unused-variable -Wno-unused-value
LDFLAGS += -Wl,-rpath,'$$ORIGIN' -g -ldl -shared
DEPS = vmmdll.h
OBJ = oscompatibility.o charutil.o util.o pe.o vmm.o vmmdll.o mm_x64.o       \
      mm_x86.o mm_x86pae.o mm_pfn.o mm_vad.o mm_win.o pdb.o pluginmanager.o  \
	  ob/ob_cachemap.o ob/ob_compressed.o ob/ob_container.o ob/ob_core.o     \
	  ob/ob_map.o ob/ob_memfile.o ob/ob_set.o ob/ob_strmap.o                 \
	  statistics.o sysquery.o vmmevil.o vmmnet.o vmmproc.o vmmwininit.o      \
	  vmmwin.o vmmwinobj.o vmmwinreg.o vmmwinsvc.o m_file_handles_vads.o     \
	  m_file_modules.o m_findevil.o m_handle.o m_ldrmodules.o m_memmap.o     \
	  m_phys2virt.o m_conf.o m_vfsproc.o m_vfsroot.o m_vfsfc.o m_virt2phys.o \
	  m_winreg.o m_minidump.o m_thread.o                                     \
	  m_sys.o m_sys_driver.o m_sys_mem.o m_sys_net.o m_sys_obj.o             \
	  m_sys_proc.o m_sys_svc.o m_sys_task.o                                  \
	  fc.o m_fc_json.o m_fc_module.o m_fc_ntfs.o m_fc_proc.o m_fc_registry.o \
	  m_fc_thread.o m_fc_timeline.o                                          \
	  infodb.o sqlite/sqlite3.o


%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

vmm: $(OBJ)
	cp ../files/leechcore.so . || cp ../../LeechCore*/files/leechcore.so . || true
	$(CC) -o $@ $^ $(CFLAGS) -o vmm.so $(LDFLAGS)
	mv vmm.so ../files/
	mv leechcore.so ../files/
	rm -f *.o || true
	rm -f */*.o || true
	rm -f *.so || true
	true

clean:
	rm -f *.o || true
	rm -f */*.o || true
	rm -f *.so || true
