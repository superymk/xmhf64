# makefile for xmhf-startup component
# author: amit vasudevan (amitvasudevan@acm.org)

# source files
AS_SOURCES =

C_SOURCES =  runtime.c
C_SOURCES += rntm-data.c

C_SOURCES += ./arch/x86/rntm-x86-data.c
C_SOURCES += ./arch/x86/rntm-x86-dmap.c

current_dir = $(shell pwd)
EXTRA_CLEAN = $(current_dir)/*.o $(current_dir)/arch/x86/*.o $(current_dir)/arch/x86/vmx/*.o $(current_dir)/arch/x86/svm/*.o

# targets
include ../runtime.mk

