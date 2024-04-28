/*
 * @XMHF_LICENSE_HEADER_START@
 *
 * eXtensible, Modular Hypervisor Framework (XMHF)
 * Copyright (c) 2009-2012 Carnegie Mellon University
 * Copyright (c) 2010-2012 VDG Inc.
 * All Rights Reserved.
 *
 * Developed by: XMHF Team
 *               Carnegie Mellon University / CyLab
 *               VDG Inc.
 *               http://xmhf.org
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in
 * the documentation and/or other materials provided with the
 * distribution.
 *
 * Neither the names of Carnegie Mellon or VDG Inc, nor the names of
 * its contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * @XMHF_LICENSE_HEADER_END@
 */

//author: Eric Li (xiaoyili@andrew.cmu.edu)
//        Miao Yu (superymk@cmu.edu)

/// @brief Common header files for EFI support.

#ifndef _XMHF_BOOTLOADER_EFI_HEADER
#define _XMHF_BOOTLOADER_EFI_HEADER

/* Hack: GCC cannot find <wchar.h>, so manually define wchar_t here */
typedef short unsigned int wchar_t;
/* Hack: tomcrypt assumes wchar_t is 4 bytes, so don't include it */
#define TOMCRYPT_H_
/* Include XMHF headers */
#include <xmhf.h>
/* Hack: gnu-efi provides efistdarg.h, so undefine related macros here */
#undef va_start
#undef va_arg
#undef va_end

#include <efi.h>
#include <efilib.h>

#include "os_bootloader.h"

/* HALT() contains an infinite loop to indicate that it never exits */
#define HALT() do { __asm__ __volatile__ ("hlt\r\n"); } while (1)

#define UEFI_CALL(...) \
	do { \
		EFI_STATUS _status; \
		_status = uefi_call_wrapper(__VA_ARGS__); \
		if (EFI_ERROR(_status)) { \
			printf("UEFI_CALL(%s) error at %s:%d (status = 0x%08lx)\n", \
				   #__VA_ARGS__, __FILE__, __LINE__, _status); \
			Print(L"UEFI_CALL error at line %d, returns EFI_STATUS: %r\n", __LINE__, _status); \
			HALT(); \
		} \
	} while(0)


extern int efi_file_measure_and_extend_in_tpm(EFI_FILE_HANDLE volume, CHAR16* filepath, int tpm_locality, int tpm_pcr);

/// @brief Return size of opened file.
/// @param file_handle opened file handle.
/// @return size of file.
extern UINT64 efi_file_get_size(EFI_FILE_HANDLE file_handle);

#endif // _XMHF_BOOTLOADER_EFI_HEADER