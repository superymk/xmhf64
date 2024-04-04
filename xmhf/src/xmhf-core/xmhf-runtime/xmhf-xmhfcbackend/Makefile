# makefile for xmhf-xmhfcbackend (libxmhfc backend component)
# author: amit vasudevan (amitvasudevan@acm.org)

# source files
AS_SOURCES =
C_SOURCES =  xmhfc-putchar.c
C_SOURCES += ./stl/xmhfc-bitmap.c
C_SOURCES += ./stl/xmhfc-dlist.c

C_SOURCES_BL =  xmhfc-putchar.c

current_dir = $(shell pwd)
EXTRA_CLEAN = $(current_dir)/*.o $(current_dir)/stl/*.o

# targets
include ../runtime.mk

