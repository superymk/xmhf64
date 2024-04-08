# makefile for xmhf-parteventhub (EMHF partition event-hub component)
# author: amit vasudevan (amitvasudevan@acm.org)

# source files
AS_SOURCES =  ./arch/x86/svm/peh-x86svm-entry.S
AS_SOURCES += ./arch/x86/vmx/peh-x86vmx-entry.S

C_SOURCES =  ./arch/x86/svm/peh-x86svm-main.c
C_SOURCES += ./arch/x86/vmx/peh-x86vmx-main.c
C_SOURCES += ./arch/x86/vmx/peh-x86-safemsr.c
ifeq ($(UPDATE_INTEL_UCODE), y)
C_SOURCES += ./arch/x86/vmx/peh-x86vmx-ucode.c
C_SOURCES += ./arch/x86/vmx/peh-x86vmx-ucode-data.c
endif

current_dir = $(shell pwd)
EXTRA_CLEAN = $(current_dir)/*.o $(current_dir)/arch/x86/*.o $(current_dir)/arch/x86/vmx/*.o $(current_dir)/arch/x86/svm/*.o

# targets
include ../runtime.mk

