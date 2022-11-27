CC=gcc
CFLAGS= -I. -I../includes -D LINUX  -L. -l:vmm.so -shared -fPIC -fvisibility=hidden `pkg-config python3 --libs --cflags`
# DEBUG FLAGS BELOW
# CFLAGS  += -g -O0 -Wextra -Wno-unused-parameter -Wno-cast-function-type
# DEBUG FLAGS ABOVE
CFLAGS  += -fPIE -fPIC -pie -fstack-protector -D_FORTIFY_SOURCE=2 -O1 -Wl,-z,noexecstack
CFLAGS  += -Wall -Wno-format-truncation -Wno-enum-compare -Wno-pointer-sign -Wno-multichar -Wno-unused-variable -Wno-unused-value
CFLAGS  += -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast
LDFLAGS += -L../files -Wl,-rpath,'$$ORIGIN' -g -ldl -shared
DEPS = 
OBJ = oscompatibility.c vmmpycplugin.c vmmpyc.c                               \
      vmmpyc_maps.c vmmpyc_process.c vmmpyc_regvalue.c vmmpyc_virtualmemory.c \
	  vmmpyc_module.c vmmpyc_processmaps.c vmmpyc_scattermemory.c             \
	  vmmpyc_vmm.c version.h vmmpyc_modulemaps.c vmmpyc_reghive.c             \
	  vmmpyc_util.c vmmpyc_pdb.c vmmpyc_regkey.c vmmpyc_vfs.c vmmpyc.h        \
	  vmmpyc_kernel.c vmmpyc_physicalmemory.c vmmpyc_regmemory.c              \
	  vmmpyc_virtualmachine.c

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
