#
# Makefile for memprocfs_fuse. Note that this build script requires MemProcFS
# and LeechCore to be built prior. Both shared libraries should be located in
# the folder '../files/'.
#
CC=gcc
CFLAGS	+= -I. -I../includes -D LINUX -D_FILE_OFFSET_BITS=64 -pthread `pkg-config fuse --cflags`
CFLAGS  += -fPIE -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O1
CFLAGS	+= -Wall -Wno-multichar -Wno-unused-variable -Wno-unused-parameter -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast
ifeq ($(shell basename $(CC)),gcc)
    CFLAGS  += -pie
	#DEBUG FLAGS BELOW
	#CFLAGS  += -g -O0 -Wextra
endif
LDFLAGS += -Wl,-rpath,'$$ORIGIN' -ldl -L. -l:vmm.so -Wl,-z,noexecstack `pkg-config fuse --libs`
DEPS = vfs.h
OBJ  = oscompatibility.o charutil.o vfslist.o memprocfs_fuse.o ob/ob_cachemap.o ob/ob_core.o ob/ob_map.o ob/ob_set.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

memprocfs: $(OBJ)
	cp ../files/leechcore.so . || true
	cp ../files/vmm.so . || true
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)
	mv memprocfs ../files/ || true
	rm -f *.o || true
	rm -f */*.o || true
	rm -f *.so || true

clean:
	rm -f *.o || true
	rm -f */*.o || true
	rm -f *.so || true
