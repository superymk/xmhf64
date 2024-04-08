# makefile for EMHF debug component
# author: amit vasudevan (amitvasudevan@acm.org)

# source files
AS_SOURCES =
AS_SOURCES_BL =

C_SOURCES = dbg-interface.c 
C_SOURCES += ./arch/x86/emhf_debug_arch.c

ifeq ($(DEBUG_SERIAL), y)
C_SOURCES += ./arch/x86/dbg-x86-uart.c
C_SOURCES += ./arch/x86/dbg-x86-pci-16550.c
endif

ifeq ($(DEBUG_VGA), y)
C_SOURCES += ./arch/x86/dbg-x86-vgamem.c
endif

# ifeq ($(DEBUG_EVENT_LOGGER), y)
C_SOURCES += dbg-event-logger.c
# endif

C_SOURCES_BL = $(C_SOURCES)

EXTRA_CLEAN = lib.a lib.bl.a

current_dir = $(shell pwd)
EXTRA_CLEAN += $(current_dir)/*.o $(current_dir)/arch/x86/*.o $(current_dir)/arch/x86/vmx/*.o $(current_dir)/arch/x86/svm/*.o

# targets
include ../runtime.mk

all: lib.a

lib.a: $(OBJECTS)
	$(AR) rvs $@ $^

# If runtime is amd64, compile bootloader version of this library
ifeq ($(TARGET_SUBARCH), amd64)
all: lib.bl.a

lib.bl.a: $(OBJECTS_BL)
	$(AR) rvs $@ $^
endif

