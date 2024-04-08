# makefile for xmhf-nested (XMHF nested virtualization)
# author: Eric Li (xiaoyili@andrew.cmu.edu)

# source files
AS_SOURCES =

C_SOURCES =  ./arch/x86/vmx/nested-x86vmx-handler1.c
C_SOURCES += ./arch/x86/vmx/nested-x86vmx-handler2.c
C_SOURCES += ./arch/x86/vmx/nested-x86vmx-vmcs12.c
C_SOURCES += ./arch/x86/vmx/nested-x86vmx-ept12.c

current_dir = $(shell pwd)
EXTRA_CLEAN = $(current_dir)/*.o $(current_dir)/arch/x86/*.o $(current_dir)/arch/x86/vmx/*.o $(current_dir)/arch/x86/svm/*.o

# targets
include ../runtime.mk

