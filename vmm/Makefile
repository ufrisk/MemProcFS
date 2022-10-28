#
# NOTE! PACKAGE DEPENDENCY ON LeechCore:
#       The build script require leechcore.so built from the leechcore project
#       which is found at https://github.com/ufrisk/LeechCore to build. This
#       file is assumed to exist in either of the directories: 
#       . (current), ../files, ../../LeechCore*/files
#
CC=gcc
CFLAGS  += -std=c11 -I. -I../includes -D LINUX -D _GNU_SOURCE -D SQLITE_THREADSAFE=2 -D SQLITE_CORE -shared -fPIC -l:leechcore.so -fvisibility=hidden -L. -lm -pthread `pkg-config liblz4 openssl --libs --cflags`
#CFLAGS  += -g -O0 -Wextra -Wno-unused-parameter -Wno-cast-function-type
CFLAGS  += -fPIE -fPIC -pie -fstack-protector -D_FORTIFY_SOURCE=2 -O1 -Wl,-z,noexecstack
CFLAGS  += -Wall -Wno-format-truncation -Wno-enum-compare -Wno-pointer-sign -Wno-multichar -Wno-unused-variable -Wno-unused-value
CFLAGS  += -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast
LDFLAGS += -Wl,-rpath,'$$ORIGIN' -g -ldl -shared
DEPS = vmmdll.h
OBJ = oscompatibility.o charutil.o util.o pe.o vmmdll.o vmmdll_core.o vmmdll_scatter.o     \
	  vmm.o mm_x64.o mm_x86.o mm_x86pae.o mm_pfn.o mm_vad.o mm_win.o fc.o    \
	  pluginmanager.o pdb.o infodb.o sqlite/sqlite3.o                        \
	  ob/ob_cachemap.o ob/ob_compressed.o ob/ob_container.o ob/ob_core.o     \
	  ob/ob_counter.o ob/ob_map.o ob/ob_memfile.o ob/ob_set.o ob/ob_strmap.o \
	  statistics.o sysquery.o vmmevil.o vmmheap.o vmmlog.o vmmnet.o          \
	  vmmproc.o vmmwininit.o vmmwin.o vmmwinobj.o vmmwinpool.o vmmwinreg.o   \
	  vmmwinsvc.o vmmwork.o                                                  \
	  m_vfsfc.o m_vfsproc.o m_vfsroot.o m_conf.o m_winreg.o                  \
	  m_fc_csv.o m_fc_handle.o m_fc_json.o m_fc_module.o m_fc_ntfs.o         \
	  m_fc_proc.o m_fc_registry.o m_fc_sys.o m_fc_thread.o m_fc_timeline.o   \
	  m_file_handles_vads.o m_file_modules.o                                 \
	  m_findevil.o m_misc_bitlocker.o m_misc_web.o m_misc_view.o             \
	  m_phys2virt.o m_proc_handle.o m_proc_heap.o m_proc_ldrmodules.o        \
	  m_proc_memmap.o m_proc_minidump.o m_proc_thread.o m_proc_token.o       \
	  m_search.o m_sys.o m_sys_driver.o m_sys_mem.o m_sys_net.o m_sys_obj.o  \
	  m_sys_pool.c m_sys_proc.o m_sys_svc.o m_sys_task.o m_sys_user.o        \
	  m_virt2phys.o

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
