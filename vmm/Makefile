#
# NOTE! PACKAGE DEPENDENCY ON LeechCore:
#       The build script require leechcore.so built from the leechcore project
#       which is found at https://github.com/ufrisk/LeechCore to build. This
#       file is assumed to exist in either of the directories: 
#       . (current), ../files, ../../LeechCore*/files
#
CC=gcc
CFLAGS  += -std=c11 -I. -I../includes -D LINUX -D _GNU_SOURCE -D SQLITE_THREADSAFE=2 -D SQLITE_CORE -fPIC -fvisibility=hidden -pthread
CFLAGS  += -fPIE -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O1
CFLAGS  += -Wall -Wno-format-truncation -Wno-enum-compare -Wno-pointer-sign -Wno-multichar -Wno-unused-variable -Wno-unused-value
CFLAGS  += -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast
ifeq ($(shell basename $(CC)),gcc)
    CFLAGS  += -pie
	# DEBUG FLAGS BELOW
	#export ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:detect_invalid_pointer_pairs=2
	#CFLAGS  += -g -O0 -Wextra -Wno-unused-parameter -Wno-cast-function-type
	#CFLAGS  += -fsanitize=address -fsanitize=leak -fno-omit-frame-pointer -fsanitize=undefined -fsanitize=bounds-strict -fsanitize=float-divide-by-zero -fsanitize=float-cast-overflow
	#CFLAGS  += -fsanitize=pointer-compare -fsanitize=pointer-subtract -fanalyzer
	# DEBUG FLAGS ABOVE
endif
LDFLAGS += -Wl,-rpath,'$$ORIGIN' -g -ldl -shared -L. -l:leechcore.so -lm -Wl,-z,noexecstack
DEPS = vmmdll.h
OBJ = oscompatibility.o charutil.o util.o pe.o vmmdll.o vmmdll_core.o        \
	  vmmdll_remote.o vmmdll_scatter.o vmm.o vmmex_light.o fc.o              \
	  mm/mm_arm64.o mm/mm_x64.o mm/mm_x86.o mm/mm_x86pae.o mm/mm_pfn.o       \
	  mm/mm_vad.o mm/mm_win.o                                                \
	  pluginmanager.o pdb.o infodb.o                                         \
	  ext/lz4.o ext/miniz.o ext/sha256.o ext/sqlite3.o                       \
	  ob/ob_bytequeue.o ob/ob_cachemap.o ob/ob_compressed.o                  \
	  ob/ob_container.o ob/ob_core.o ob/ob_counter.o ob/ob_map.o             \
	  ob/ob_memfile.o ob/ob_set.o ob/ob_strmap.o                             \
	  statistics.o sysquery.o vmmheap.o vmmlog.o vmmnet.o                    \
	  vmmproc.o vmmvm.o vmmwininit.o vmmwin.o vmmwinobj.o vmmwinpool.o       \
	  vmmwinreg.o vmmwinsvc.o vmmwinthread.o vmmuserconfig.o vmmwork.o       \
	  vmmyarautil.o vmmyarawrap.o                                            \
	  modules/m_vfsroot.o modules/m_vfsproc.o modules/m_vfsfc.o              \
	  modules/m_conf.o modules/m_vm.o modules/m_winreg.o                     \
	  modules/m_fc_csv.o modules/m_fc_file.o modules/m_fc_findevil.o         \
	  modules/m_fc_handle.o modules/m_fc_json.o modules/m_fc_module.o        \
	  modules/m_fc_ntfs.o modules/m_fc_prefetch.o modules/m_fc_proc.o        \
	  modules/m_fc_registry.o modules/m_fc_sys.o modules/m_fc_thread.o       \
	  modules/m_fc_timeline.o modules/m_fc_web.o modules/m_fc_yara.o         \
	  modules/m_evil_apc1.o modules/m_evil_av1.o modules/m_evil_entropy.o    \
	  modules/m_evil_kern1.o modules/m_evil_kernproc1.o                      \
	  modules/m_evil_proc1.o modules/m_evil_proc2.o modules/m_evil_proc3.o   \
	  modules/m_evil_thread1.o                                               \
	  modules/m_misc_bitlocker.o modules/m_misc_eventlog.o                   \
	  modules/m_misc_procinfo.o modules/m_misc_view.o                        \
	  modules/m_sys.o modules/m_sys_driver.o modules/m_sys_mem.o             \
	  modules/m_sys_net.o modules/m_sys_netdns.o modules/m_sys_obj.o         \
	  modules/m_sys_pool.o modules/m_sys_proc.o modules/m_sys_svc.o          \
	  modules/m_sys_syscall.o modules/m_sys_sysinfo.o modules/m_sys_task.o   \
	  modules/m_sys_user.o                                                   \
	  modules/m_phys2virt.o modules/m_search.o modules/m_searchyara.o        \
	  modules/m_proc_console.o modules/m_proc_file_handles_vads.o            \
	  modules/m_proc_file_modules.o modules/m_proc_handle.o                  \
	  modules/m_proc_heap.o modules/m_proc_ldrmodules.o                      \
	  modules/m_proc_memmap.o modules/m_proc_minidump.o                      \
	  modules/m_proc_thread.o modules/m_proc_token.o                         \
	  modules/m_proc_virt2phys.o

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
