# Compile amd64 pal_demo for Linux on amd64 Linux:
#   make
# Compile i386 pal_demo for Linux on amd64 Debian:
#   make CC=i686-linux-gnu-gcc LD=i686-linux-gnu-ld
# Compile i386 pal_demo for Linux on amd64 Fedora:
#   make I386=y
# Compile i386 pal_demo for Windows on Linux:
#   make CC=i686-w64-mingw32-gcc LD=i686-w64-mingw32-ld
# Compile amd64 pal_demo for Windows on Linux:
#   make CC=x86_64-w64-mingw32-gcc LD=x86_64-w64-mingw32-ld

# -fno-stack-protector: hint from https://stackoverflow.com/questions/2340259/
CFLAGS := -g -I../src/include -Wall -Werror -fno-stack-protector

BINS = main test test_args
PAL_OBJS = pal.o caller.o
VMCALL_OFFSET = 0U

ifeq ($(WINDOWS), y)
	CFLAGS += -DWINDOWS
endif
ifeq ($(I386), y)
	CFLAGS += -m32
	LDFLAGS += -m32
endif
CFLAGS += -DVMCALL_OFFSET=$(VMCALL_OFFSET)

ifeq ($(CC), x86_64-w64-mingw32-gcc)
PAL_OBJS += translate.o
CFLAGS += -DTRANSLATE
endif

all: $(BINS)

main: main.o $(PAL_OBJS)
test_args: test_args.o $(PAL_OBJS)
test: test.c

pal.o: pal.c
	$(CC) $(CFLAGS) -fno-pic -c -o $@ $^

.PHONY: clean
clean:
	rm -rf *.o $(patsubst %,%.exe,$(BINS)) $(BINS)

