# makefile for xmhf-partition (EMHF component for handling partition
# setup and instantiation)
# author: amit vasudevan (amitvasudevan@acm.org)

# source files
AS_SOURCES =  ./arch/x86/vmx/part-x86vmx-sup.S
AS_SOURCES += ./arch/x86/svm/part-x86svm-sup.S

C_SOURCES =  part-interface.c
C_SOURCES += ./arch/x86/part-x86.c
C_SOURCES += ./arch/x86/vmx/part-x86vmx.c
C_SOURCES += ./arch/x86/svm/part-x86svm.c

current_dir = $(shell pwd)
EXTRA_CLEAN = $(current_dir)/*.o $(current_dir)/arch/x86/*.o $(current_dir)/arch/x86/vmx/*.o $(current_dir)/arch/x86/svm/*.o

# targets
include ../runtime.mk

