# makefile for "init"
# author: amit vasudevan (amitvasudevan@acm.org)

CFLAGS := $(BCFLAGS)
ASFLAGS := $(BASFLAGS)
CCLIB := $(BCCLIB)
current_dir = $(shell pwd)

# source files
C_SOURCES =
AS_SOURCES =

# DRT
ifeq ($(DRT), y)
C_SOURCES += txt.c txt_acmod.c txt_heap.c txt_hash.c
endif

C_SOURCES += common/init.c smp.c cmdline.c


OBJECTS = $(patsubst %.S, %.o, $(AS_SOURCES))
OBJECTS += $(patsubst %.c, %.o, $(C_SOURCES))



# LibTPM
# CFLAGS += -I$(current_dir)/libtpm


ifeq ($(TARGET_UEFI), y)
OBJECTS += $(GNUEFI_BUILD)/x86_64/gnuefi/crt0-efi-x86_64.o
# Note: entry-efi.o is compiled differently with other object files
endif

OBJECTS_PRECOMPILED = ../xmhf-runtime/xmhf-debug/lib.a

OBJECTS_PRECOMPILED += ../xmhf-runtime/xmhf-tpm/tpm-interface.o
OBJECTS_PRECOMPILED += ../xmhf-runtime/xmhf-tpm/arch/x86/tpm-x86.o
OBJECTS_PRECOMPILED += ../xmhf-runtime/xmhf-tpm/arch/x86/svm/tpm-x86svm.o
OBJECTS_PRECOMPILED += ../xmhf-runtime/xmhf-tpm/arch/x86/vmx/tpm-x86vmx.o

OBJECTS_PRECOMPILED += ../xmhf-runtime/xmhf-baseplatform/arch/x86/bplt-x86-pci.o
OBJECTS_PRECOMPILED += ../xmhf-runtime/xmhf-baseplatform/arch/x86/bplt-x86-acpi.o
OBJECTS_PRECOMPILED += ../xmhf-runtime/xmhf-baseplatform/arch/x86/bplt-x86-pit.o
ifeq ($(TARGET_UEFI), y)
OBJECTS_PRECOMPILED += ../xmhf-runtime/xmhf-baseplatform/arch/x86/bplt-x86-amd64-smplock.o
else
OBJECTS_PRECOMPILED += ../xmhf-runtime/xmhf-baseplatform/arch/x86/bplt-x86-i386-smplock.o
endif
OBJECTS_PRECOMPILED += ../xmhf-runtime/xmhf-baseplatform/arch/x86/bplt-x86-addressing.o
OBJECTS_PRECOMPILED += ../xmhf-runtime/xmhf-baseplatform/arch/x86/bplt-x86-cpu.o

ifeq ($(DRT), y)
OBJECTS_PRECOMPILED += ../xmhf-runtime/xmhf-baseplatform/arch/x86/vmx/bplt-x86vmx-mtrrs-common.o
OBJECTS_PRECOMPILED += ../xmhf-runtime/xmhf-baseplatform/arch/x86/vmx/bplt-x86vmx-mtrrs-bootloader.o
endif

# FIXME: This is overly general; init/ doesn't need all of these
CFLAGS += $(ADDL_INCLUDES_BOOTLOADER)
CFLAGS += -I$(current_dir)/include

# separate from OBJECTS_PRECOMPILED becasue needs to come after libs on link line
OBJECTS_PRECOMPILED_LIBBACKENDS = ../xmhf-runtime/xmhf-xmhfcbackend/xmhfc-putchar.o
OBJECTS_PRECOMPILED_LIBBACKENDS += ../xmhf-runtime/xmhf-debug/lib.a

I_SOURCES = $(wildcard $(INCLUDEDIR)/*.h)


# If runtime is amd64, bootloader need to switch to precompiled object files
# with special CFLAGS.
ifeq ($(TARGET_SUBARCH), amd64)
OBJECTS_PRECOMPILED := $(patsubst %.o, %.bl.o, $(OBJECTS_PRECOMPILED))
OBJECTS_PRECOMPILED := $(patsubst %.a, %.bl.a, $(OBJECTS_PRECOMPILED))
OBJECTS_PRECOMPILED_LIBBACKENDS := $(patsubst %.o, %.bl.o, $(OBJECTS_PRECOMPILED_LIBBACKENDS))
OBJECTS_PRECOMPILED_LIBBACKENDS := $(patsubst %.a, %.bl.a, $(OBJECTS_PRECOMPILED_LIBBACKENDS))
endif


# NOTE: THIS IS THE init MODULE.  IT IS COMPLETELY UNTRUSTED.  THESE
# VALUES ARE HERE SIMPLY TO AID IN DEVELOPMENT AND DEBUGGING, TO STOP
# EARLY IN THE EVENT OF MISTAKES.  DO NOT RELY ON THEM!

# RUNTIME_INTEGRITY_HASH should be set by parent Makefile
ifdef RUNTIME_INTEGRITY_HASH
CFLAGS += -D___RUNTIME_INTEGRITY_HASH___=\"$(RUNTIME_INTEGRITY_HASH)\"
endif
# SLABOVE64K_INTEGRITY_HASH should be set by parent Makefile
ifdef SLABOVE64K_INTEGRITY_HASH
CFLAGS += -D___SLABOVE64K_INTEGRITY_HASH___=\"$(SLABOVE64K_INTEGRITY_HASH)\"
endif
# SLBELOW64K_INTEGRITY_HASH should be set by parent Makefile
ifdef SLBELOW64K_INTEGRITY_HASH
CFLAGS += -D___SLBELOW64K_INTEGRITY_HASH___=\"$(SLBELOW64K_INTEGRITY_HASH)\"
endif


# targets
.PHONY: all
ifeq ($(TARGET_UEFI), y)
all: init-$(TARGET_HWPLATFORM)-$(TARGET_SUBARCH).efi
else
all: init-$(TARGET_HWPLATFORM)-$(TARGET_SUBARCH).bin
endif

# FIXME: ADDL_LIBS is overly general; init/ doesn't need all of them
init-$(TARGET_HWPLATFORM)-$(TARGET_SUBARCH).bin: libtpm hash bios $(OBJECTS) $(OBJECTS_PRECOMPILED) init.lds.S
	$(LD) $(LDFLAGS) -T init.lds.S -o init.exe $(OBJECTS) $(OBJECTS_PRECOMPILED) ./libtpm/libtpm.a ./hash/lib-hash.a ./bios/lib-bios.a $(ADDL_LIBS_BOOTLOADER) $(OBJECTS_PRECOMPILED_LIBBACKENDS) -L$(CCLIB) -lgcc
	$(CP) init.exe init_syms.exe
	$(STRIP) -s init.exe
	$(OBJCOPY) --output-format=binary init.exe init-$(TARGET_HWPLATFORM)-$(TARGET_SUBARCH).bin

ifeq ($(TARGET_UEFI), y)

# LD flags from gnu-efi tutorial
EFI_LDFLAGS = -shared -Bsymbolic -L$(GNUEFI_BUILD)/x86_64/lib
EFI_LDFLAGS += -L$(GNUEFI_BUILD)/x86_64/gnuefi
EFI_LDLIBS = -lgnuefi -lefi

# OBJCOPY flags from gnu-efi tutorial
OBJCOPY_FLAGS = -j .text -j .sdata -j .data -j .dynamic -j .dynsym  -j .rel
OBJCOPY_FLAGS += -j .rela -j .rel.* -j .rela.* -j .reloc
OBJCOPY_FLAGS += --target efi-app-x86_64 --subsystem=12


init-$(TARGET_HWPLATFORM)-$(TARGET_SUBARCH).so: libtpm hash efi $(OBJECTS) $(OBJECTS_PRECOMPILED) $(GNUEFI_SRC)/gnuefi/elf_x86_64_efi.lds
	$(LD) $(EFI_LDFLAGS) -T$(GNUEFI_SRC)/gnuefi/elf_x86_64_efi.lds $(OBJECTS) $(OBJECTS_PRECOMPILED) ./libtpm/libtpm.a ./hash/lib-hash.a ./efi/lib-efi.a $(ADDL_LIBS_BOOTLOADER) $(OBJECTS_PRECOMPILED_LIBBACKENDS) $(EFI_LDLIBS) -o $@
	chmod -x $@

init-$(TARGET_HWPLATFORM)-$(TARGET_SUBARCH).efi: init-$(TARGET_HWPLATFORM)-$(TARGET_SUBARCH).so
	objcopy $(OBJCOPY_FLAGS) $^ $@
	chmod -x $@

endif


.PHONY: libtpm
libtpm:
	@$(MAKE) -C ./libtpm all

.PHONY: hash
hash:
	@$(MAKE) -C ./hash all

.PHONY: bios
bios:
	@$(MAKE) -C ./bios all

.PHONY: efi
efi:
	@$(MAKE) -C ./efi all

.PHONY: clean
clean:
	$(RM) -rf *.o
	$(RM) -rf *.exe
	$(RM) -rf *.bin
	$(RM) -rf *.gz
	$(RM) -rf *.so
	$(RM) -rf *.efi
	
	cd libtpm && $(MAKE) -w clean
	cd hash && $(MAKE) -w clean
	cd bios && $(MAKE) -w clean
	cd efi && $(MAKE) -w clean