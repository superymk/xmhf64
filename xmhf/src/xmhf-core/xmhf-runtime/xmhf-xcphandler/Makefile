# makefile for xmhf-xcphandler (EMHF exception handler component)
# author: amit vasudevan (amitvasudevan@acm.org)

# source files
AS_SOURCES = ./arch/x86/xcph-stubs-$(TARGET_SUBARCH).S
C_SOURCES =  xcph-interface.c
C_SOURCES += ./arch/x86/xcph-x86.c

current_dir = $(shell pwd)
EXTRA_CLEAN = $(current_dir)/*.o $(current_dir)/arch/x86/*.o $(current_dir)/arch/x86/vmx/*.o $(current_dir)/arch/x86/svm/*.o

# targets
include ../runtime.mk

