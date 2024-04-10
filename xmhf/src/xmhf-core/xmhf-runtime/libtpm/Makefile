# makefile for xmhf-nested (XMHF nested virtualization)
# author: Eric Li (xiaoyili@andrew.cmu.edu)

# source files
AS_SOURCES =

C_SOURCES =  ./tpm_12.c
C_SOURCES += ./tpm_20.c
C_SOURCES += ./tpm.c

current_dir = $(shell pwd)
EXTRA_CLEAN = $(current_dir)/*.o $(current_dir)/arch/x86/*.o $(current_dir)/arch/x86/vmx/*.o $(current_dir)/arch/x86/svm/*.o

# targets
include ../runtime.mk

