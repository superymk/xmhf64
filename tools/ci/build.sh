#!/bin/bash
#
# The following license and copyright notice applies to all content in
# this repository where some other license does not take precedence. In
# particular, notices in sub-project directories and individual source
# files take precedence over this file.
#
# See COPYING for more information.
#
# eXtensible, Modular Hypervisor Framework 64 (XMHF64)
# Copyright (c) 2023 Eric Li
# All Rights Reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in
# the documentation and/or other materials provided with the
# distribution.
#
# Neither the name of the copyright holder nor the names of
# its contributors may be used to endorse or promote products derived
# from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
# TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

# Usage: build.sh subarch [arguments [...]]
# subarch: i386 or amd64 or uefi
# arguments:
#   --drt: enable DRT (--disable-drt)
#   --dmap: enable DMAP (--disable-dmap)
#   --vga: use VGA instead of serial (--disable-debug-serial --enable-debug-vga)
#   --event-logger: enable event logger (--enable-debug-event-logger)
#   --no-dbg: do not use QEMU debug workarounds (--enable-debug-qemu)
#   --no-ucode: disable Intel microcode update (--enable-update-intel-ucode)
#   --app APP: set hypapp, default is "hypapps/trustvisor" (--with-approot)
#   --mem MEM: if amd64, set physical memory, default is 0x140000000 (5GiB)
#   --no-x2apic: hide x2APIC to workaround a bug (--enable-hide-x2apic)
#   --no-rt-bss: skip runtime bss in image (--enable-skip-runtime-bss)
#   --no-bl-hash: skip bootloader hashing (--enable-skip-bootloader-hash)
#   --no-init-smp: disable SMP in bootloader (--enable-skip-init-smp)
#   --iss NUM: set number of extra INIT-SIPI-SIPI (--with-extra-ap-init-count)
#   --sl-base BASE: set SL+RT base to BASE instead of 256M (--with-sl-base)
#   --pie: make XMHF runtime PIE (--enable-runtime-pie)
#   fast: equivalent to --no-rt-bss --no-bl-hash (For running XMHF quickly)
#   nv: enable nested virtualization (--enable-nested-virtualization)
#   no_nv: disable nested virtualization (--disable-nested-virtualization)
#   --ept-num EPT_NUM: # max active ept (--with-vmx-nested-max-active-ept)
#   --ept-pool EPT_POOL: pool for ept (--with-vmx-nested-ept02-page-pool-size)
#   release: equivalent to --drt --dmap --no-dbg (For GitHub actions)
#   debug: ignored (For GitHub actions)
#   O0: ignored (For GitHub actions)
#   O3: enable -O3 optimization, etc. (For GitHub actions)
#   circleci: enable --enable-optimize-nested-virt workaround for Circle CI
#   -n: print autogen.sh and configure options, do not run them

set -e

# Information about compiler's platform
LINUX_BASE=""					# DEB or RPM
LINUX_BIT=$(getconf LONG_BIT)	# 32 or 64

# Information about XMHF
APPROOT="hypapps/trustvisor"
SUBARCH=""
DRT="n"
DMAP="n"
VGA="n"
EVENT_LOGGER="n"
QEMU="y"
UCODE="y"
AMD64MEM="0x140000000"
DRY_RUN="n"
CIRCLE_CI="n"
NO_X2APIC="n"
NO_RT_BSS="n"
NO_BL_HASH="n"
NO_INIT_SMP="n"
EXTRA_AP_INIT_COUNT="0"
SL_BASE="0x10000000"
PIE="n"
NV="y"
EPT_NUM="8"
EPT_POOL="512"
OPT=""

# Determine LINUX_BASE (may not be 100% correct all the time)
if [ -f "/etc/debian_version" ]; then
	# DEB-based Linux (e.g. Debian, Ubuntu)
	LINUX_BASE="DEB"
else if [ -f "/etc/redhat-release" ]; then
	# RPM-based Linux (e.g. Fedora)
	LINUX_BASE="RPM"
else
	echo 'Error: build.sh does not know about OS it is running on.'; exit 1
fi; fi

# Check LINUX_BIT
case "$LINUX_BIT" in
	32)
		;;
	64)
		;;
	*)
		echo 'Error: unknown result from `getconf LONG_BIT`'; exit 1
		;;
esac

# Determine SUBARCH
case "$1" in
	i386)
		SUBARCH="i386"
		UEFI="n"
		;;
	amd64)
		SUBARCH="amd64"
		UEFI="n"
		;;
	uefi)
		SUBARCH="amd64"
		UEFI="y"
		;;
	*)
		echo 'Error: subarch incorrect, should be i386, amd64, or uefi'; exit 1
		;;
esac
shift

# Process other arguments
while [ "$#" -gt 0 ]; do
	case "$1" in
		--drt)
            # DRT="y" # Force disable DRT because (1) We need to separate Intel code and AMD code to reduce its size, 
            # (2) current implementation is insecure, see [Issue 139]
			DRT="n"
			;;
		--dmap)
			DMAP="y"
			;;
		--vga)
			VGA="y"
			;;
		--event-logger)
			EVENT_LOGGER="y"
			;;
		--no-dbg)
			QEMU="n"
			;;
		--no-ucode)
			UCODE="n"
			;;
		--app)
			APPROOT="$2"
			shift
			;;
		--mem)
			AMD64MEM="$2"
			shift
			;;
		--no-x2apic)
			NO_X2APIC="y"
			;;
		--no-rt-bss)
			NO_RT_BSS="y"
			;;
		--no-bl-hash)
			NO_BL_HASH="y"
			;;
		--no-init-smp)
			NO_INIT_SMP="y"
			;;
		--iss)
			EXTRA_AP_INIT_COUNT="$2"
			shift
			;;
		--sl-base)
			SL_BASE="$2"
			shift
			;;
		--pie)
			PIE="y"
			;;
		fast)
			NO_RT_BSS="y"
			NO_BL_HASH="y"
			;;
		nv)
			NV="y"
			;;
		no_nv)
			NV="n"
			;;
		--ept-num)
			EPT_NUM="$2"
			shift
			;;
		--ept-pool)
			EPT_POOL="$2"
			shift
			;;
		release)
			# For GitHub actions
            # DRT="y" # Force disable DRT because (1) We need to separate Intel code and AMD code to reduce its size, 
            # (2) current implementation is insecure, see [Issue 139]
			DRT="n" 
			DMAP="y"
			QEMU="n"
			;;
		debug)
			# For GitHub actions
			;;
		O0)
			# For GitHub actions
			;;
		O3)
			# For GitHub actions
			OPT="O3"
			;;
		circleci)
			CIRCLE_CI="y"
			;;
		-n)
			DRY_RUN="y"
			;;
		*)
			echo "Error: unknown argument $1"; exit 1
			;;
	esac
	shift 
done

# Build configure arguments
CONF=()
CONF+=("--with-approot=$APPROOT")
CONF+=("--enable-debug-symbols")

if [ "$SUBARCH" == "i386" ]; then
	# Building i386 XMHF
	if [ "$LINUX_BASE" == "DEB" -a "$LINUX_BIT" == "64" ]; then
		# Building on amd64 Debian
		CONF+=("CC=i686-linux-gnu-gcc")
		CONF+=("LD=i686-linux-gnu-ld")
	fi
else if [ "$SUBARCH" == "amd64" ]; then
	# Building amd64 XMHF
	CONF+=("--with-target-subarch=amd64")
	CONF+=("--with-amd64-max-phys-addr=$AMD64MEM")
	if [ "$LINUX_BASE" == "DEB" -a "$LINUX_BIT" == "32" ]; then
		# Building on i386 Debian
		CONF+=("CC=x86_64-linux-gnu-gcc")
		CONF+=("LD=x86_64-linux-gnu-ld")
	fi
else
	echo 'Error: unexpected $SUBARCH'; exit 1
fi; fi

if [ "$UEFI" == "y" ]; then
	CONF+=("--enable-target-uefi")
fi

if [ "$DRT" == "n" ]; then
	CONF+=("--disable-drt")
fi

if [ "$DMAP" == "n" ]; then
	CONF+=("--disable-dmap")
fi

if [ "$VGA" == "y" ]; then
	CONF+=("--disable-debug-serial" "--enable-debug-vga")
fi

if [ "$EVENT_LOGGER" == "y" ]; then
	CONF+=("--enable-debug-event-logger")
fi

if [ "$QEMU" == "y" ]; then
	CONF+=("--enable-debug-qemu")
fi

if [ "$UCODE" == "y" ]; then
	CONF+=("--enable-update-intel-ucode")
fi

if [ "$OPT" == "O3" ]; then
	# -Wno-array-bounds is set due to a compile bug in GCC 12.
	# See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=104657
	CONF+=("--with-opt=-O3 -Wno-array-bounds")
fi

if [ "$NO_X2APIC" == "y" ]; then
	CONF+=("--enable-hide-x2apic")
fi

if [ "$NO_RT_BSS" == "y" ]; then
	CONF+=("--enable-skip-runtime-bss")
fi

if [ "$NO_BL_HASH" == "y" ]; then
	CONF+=("--enable-skip-bootloader-hash")
fi

if [ "$NO_INIT_SMP" == "y" ]; then
	CONF+=("--enable-skip-init-smp")
fi

CONF+=("--with-extra-ap-init-count=$EXTRA_AP_INIT_COUNT")

CONF+=("--with-sl-base=$SL_BASE")

if [ "$PIE" == "y" ]; then
	CONF+=("--enable-runtime-pie")
fi

if [ "$CIRCLE_CI" == "y" ]; then
	CONF+=("--enable-optimize-nested-virt")
fi

if [ "$NV" == "y" ]; then
	CONF+=("--enable-nested-virtualization")
	CONF+=("--with-vmx-nested-max-active-ept=$EPT_NUM")
	CONF+=("--with-vmx-nested-ept02-page-pool-size=$EPT_POOL")
fi

# Output configure arguments, if `-n`
if [ "$DRY_RUN" == "y" ]; then
	set +x
	echo $'\n'"./autogen.sh; ./configure ${CONF[@]@Q}"$'\n'
	exit 0
fi

# Build
set -x
./autogen.sh
./configure "${CONF[@]}"
make -j "$(nproc)"

