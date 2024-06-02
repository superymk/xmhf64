srcdir := $(dir $(lastword $(MAKEFILE_LIST)))
vpath %.c $(srcdir)
current_dir = $(shell pwd)

AS_SOURCES = $(wildcard *.S)
C_SOURCES = $(wildcard *.c)

OBJECTS = $(patsubst %.S, %.o, $(AS_SOURCES))
OBJECTS += $(patsubst %.c, %.o, $(C_SOURCES))

# C_SOURCES:= $(wildcard $(srcdir)/*.c)
# C_SOURCES:= $(patsubst $(srcdir)/%, %, $(C_SOURCES))
# OBJECTS = $(patsubst %.c, %.o, $(C_SOURCES))

I_SOURCES :=  $(wildcard $(srcdir)/include/*.h)

CFLAGS += -I$(srcdir)/../libxmhfc/include -I$(srcdir)/../libxmhfcrypto/include -I$(srcdir)/../libxmhfutil/include -I$(srcdir)/include -nostdinc -fno-builtin -nostdlib -Wall

THE_ARCHIVE = lib-efi.a

EFI_CFLAGS = -I$(GNUEFI_SRC)/inc
EFI_CFLAGS += -Wall -Werror
EFI_CFLAGS += -g
EFI_CFLAGS += -fpic -ffreestanding -fno-stack-protector -fno-stack-check
EFI_CFLAGS += -fshort-wchar -mno-red-zone -maccumulate-outgoing-args
EFI_CFLAGS += $(BCFLAGS)
EFI_CFLAGS += -Wno-strict-prototypes
EFI_CFLAGS += -I$(current_dir)/../include

# targets
.PHONY: all
all: $(THE_ARCHIVE)

$(THE_ARCHIVE): $(OBJECTS)
	$(AR) -rcs $(THE_ARCHIVE) $(OBJECTS)



%.o: %.c $(C_SOURCES) $(I_SOURCES) Makefile ../Makefile
	$(CC) -c $(EFI_CFLAGS) -o $@ $<

.PHONY: clean
clean:
	$(RM) $(OBJECTS) $(THE_ARCHIVE)

.PHONY: install-dev
install-dev:
	# Nothing to do here

