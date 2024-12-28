CC=gcc
CFLAGS= -I. -I../includes -D LINUX -fPIC -fvisibility=hidden `pkg-config python3 --cflags`
CFLAGS  += -fPIE -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O1
CFLAGS  += -Wall -Wno-format-truncation -Wno-enum-compare -Wno-pointer-sign -Wno-multichar -Wno-unused-variable -Wno-unused-value
CFLAGS  += -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast -Wno-multichar
ifeq ($(shell basename $(CC)),gcc)
    CFLAGS  += -pie
	# DEBUG FLAGS BELOW
	# CFLAGS  += -g -O0 -Wextra -Wno-unused-parameter -Wno-cast-function-type
	# DEBUG FLAGS ABOVE
endif
LDFLAGS += -L../files -Wl,-rpath,'$$ORIGIN' -g -ldl -shared -L. -l:vmm.so -Wl,-z,noexecstack `pkg-config python3 --libs`
DEPS = 
OBJ = oscompatibility.o vmmpycplugin.o vmmpyc.o                               \
      vmmpyc_maps.o vmmpyc_process.o vmmpyc_regvalue.o vmmpyc_virtualmemory.o \
	  vmmpyc_module.o vmmpyc_processmaps.o vmmpyc_scattermemory.o             \
	  vmmpyc_vmm.o vmmpyc_modulemaps.o vmmpyc_reghive.o                       \
	  vmmpyc_util.o vmmpyc_pdb.o vmmpyc_regkey.o vmmpyc_vfs.o vmmpyc.o        \
	  vmmpyc_kernel.o vmmpyc_physicalmemory.o vmmpyc_regmemory.o              \
	  vmmpyc_search.o vmmpyc_virtualmachine.o vmmpyc_yara.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

vmmpyc: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) -o vmmpyc.so $(LDFLAGS)
	mv vmmpyc.so ../files/ || true
	rm -f *.o || true
	rm -f *.so || true
	true

clean:
	rm -f *.o || true
	rm -f *.so || true
