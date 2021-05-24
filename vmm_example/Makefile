#
# NOTE! PACKAGE DEPENDENCY ON LeechCore:
#       The build script require leechcore.so built from the leechcore project
#       which is found at https://github.com/ufrisk/LeechCore to build. This
#       file is assumed to exist in either of the directories: 
#       . (current), ../files, ../../LeechCore*/files
#
CC=gcc
CFLAGS=-I. -I../includes -D LINUX -L. -l:leechcore.so -l:vmm.so -pthread
LDFLAGS=-Wl,-rpath,'$$ORIGIN' -ldl
DEPS =
OBJ = vmmdll_example.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

vmm_example: $(OBJ)
	cp ../files/leechcore.so . || cp ../../LeechCore*/files/leechcore.so . || true
	cp ../files/vmm.so . |true
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)
	rm -f *.o
	rm -f *.so

clean:
	rm -f *.o
	rm -f *.so
	rm -f vmm_example
