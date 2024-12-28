#
# NOTE! PACKAGE DEPENDENCY ON LeechCore:
#       The build script require leechcore.so built from the leechcore project
#       which is found at https://github.com/ufrisk/LeechCore to build. This
#       file is assumed to exist in either of the directories: 
#       . (current), ../files, ../../LeechCore*/files
#
CC=gcc
CFLAGS  += -std=c11 -I. -I../includes -D LINUX -D _GNU_SOURCE -fPIC -fvisibility=hidden -pthread `pkg-config liblz4 openssl --cflags`
CFLAGS  += -fPIE -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O1
CFLAGS  += -Wall -Wno-format-truncation -Wno-enum-compare -Wno-pointer-sign -Wno-multichar -Wno-unused-variable -Wno-unused-value
CFLAGS  += -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast
ifeq ($(shell basename $(CC)),gcc)
    CFLAGS  += -pie
	# DEBUG FLAGS BELOW
	#CFLAGS  += -g -O0 -Wextra -Wno-unused-parameter -Wno-cast-function-type
	# DEBUG FLAGS ABOVE
endif
LDFLAGS += -L../files -Wl,-rpath,'$$ORIGIN' -g -ldl -shared -L. -lm -l:vmm.so -Wl,-z,noexecstack `pkg-config liblz4 openssl --libs`
DEPS = vmmdll.h
OBJ = m_vmemd.o oscompatibility.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

m_vmemd: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) -o m_vmemd.so $(LDFLAGS)
	mv m_vmemd.so ../files/plugins/
	rm -f *.o || true
	rm -f */*.o || true
	rm -f *.so || true
	true

clean:
	rm -f *.o || true
	rm -f */*.o || true
	rm -f *.so || true
