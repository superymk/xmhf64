/*
 * @XMHF_LICENSE_HEADER_START@
 *
 * eXtensible, Modular Hypervisor Framework (XMHF)
 * Copyright (c) 2009-2012 Carnegie Mellon University
 * Copyright (c) 2010-2012 VDG Inc.
 * Copyright (c) 2024 Eric Li
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

//efi.c - XMHF UEFI entry point
//author: Eric Li (xiaoyili@andrew.cmu.edu)

#include "efi/header.h"

/*
 * Configuration file for XMHF bootloader.
 *
 * The configuration file should be ASCII text with '\n' as line terminator.
 * The first line is the command line.
 * The second line is the path to runtime (e.g. "\EFI\BOOT\hypervisor...bin").
 * The third line is the path to SINIT module, or empty if no SINIT module.
 */
typedef struct {
	char *free_ptr;
	char *cmdline;
	char *runtime_file;
	char *sinit_module;
} xmhf_efi_config;

/*
 * Convert char string to wchar_t string.
 *
 * src: char string to be converted.
 * Return wchar_t string. Need to be freed with FreePool.
 */
static wchar_t *xmhf_efi_bs2wcs(const char *src)
{
	size_t len = strlen(src);
	UINTN bufsize = len;
	wchar_t *dst;

	/* Check for overflow when casing size_t to UINTN */
	HALT_ON_ERRORCOND((size_t)bufsize == len);

	/* bufsize++ but check for overflow */
	{
		UINTN tmp = bufsize;
		bufsize++;
		HALT_ON_ERRORCOND(bufsize > tmp);
	}

	/* bufsize *= 2 but check for overflow */
	{
		UINTN tmp = bufsize;
		bufsize *= 2;
		HALT_ON_ERRORCOND(bufsize > tmp);
	}

	/* Allocate for new buffer */
	HALT_ON_ERRORCOND((dst = AllocatePool(bufsize)) != NULL);

	for (size_t i = 0; i < len; i++) {
		dst[i] = (wchar_t)src[i];
	}
	dst[len] = 0;

	return dst;
}

/*
 * Make sure MAX_PHYS_ADDR covers all memory on the system.
 *
 * This function never returns when MAX_PHYS_ADDR is too low.
 */
static void xmhf_efi_check_max_phys_mem(void)
{
	UINTN buf_size = 0;
	UINT8 *memory_map;
	UINTN map_key;
	UINTN desc_size;
	UINT32 desc_ver;

	/* Get buffer size */
	{
		EFI_STATUS status;
		EFI_MEMORY_DESCRIPTOR tmp;
		status = uefi_call_wrapper(BS->GetMemoryMap, 5, &buf_size,
								   &tmp, &map_key, &desc_size, &desc_ver);
		HALT_ON_ERRORCOND(status == EFI_BUFFER_TOO_SMALL);
	}

	/* Increase buf_size, ref: https://stackoverflow.com/a/39674958 */
	{
		UINTN new_buf_size = buf_size + 2 * desc_size;
		HALT_ON_ERRORCOND(new_buf_size > buf_size);
		buf_size = new_buf_size;
	}

	/* Allocate buffer */
	{
		HALT_ON_ERRORCOND((memory_map = AllocatePool(buf_size)) != NULL);
	}

	/* Get memory map */
	{
		UEFI_CALL(BS->GetMemoryMap, 5, &buf_size, memory_map, &map_key,
				  &desc_size, &desc_ver);
		HALT_ON_ERRORCOND(desc_size >= sizeof(EFI_MEMORY_DESCRIPTOR));
		HALT_ON_ERRORCOND(desc_ver == EFI_MEMORY_DESCRIPTOR_VERSION);
	}

	/* Iterate through memory map */
	{
		bool error_flag = false;

		printf("Begin UEFI GetMemoryMap result\n");
		printf("Type PhysicalStart      VirtualStart       NumberOfPages      "
			   "Attribute\n");
        Print(L"Begin UEFI GetMemoryMap result (First 20 entries)\n");
		Print(L"Type PhysicalStart      VirtualStart       NumberOfPages      "
			   "Attribute\n");
		for (UINTN i = 0; i * desc_size < buf_size; i++) {
			EFI_MEMORY_DESCRIPTOR *desc;
			UINT64 PhysEnd;

			/* Print memory map entry */
			desc = (EFI_MEMORY_DESCRIPTOR *)(memory_map + i * desc_size);
			printf("  %2d 0x%016llx 0x%016llx 0x%016llx 0x%016llx\n",
				   desc->Type, desc->PhysicalStart, desc->VirtualStart,
				   desc->NumberOfPages, desc->Attribute);
            if(i <= 20)
            {
                Print(L"  %2d 0x%016llx 0x%016llx 0x%016llx 0x%016llx\n",
                    desc->Type, desc->PhysicalStart, desc->VirtualStart,
                    desc->NumberOfPages, desc->Attribute);
            }

			/* Check the highest memory map is lower than MAX_PHYS_ADDR */
			PhysEnd = (desc->PhysicalStart +
					   (desc->NumberOfPages << PAGE_SHIFT_4K));
			HALT_ON_ERRORCOND(desc->PhysicalStart < PhysEnd);
			if (PhysEnd > MAX_PHYS_ADDR) {
				printf("The entry above exceeds MAX_PHYS_ADDR (%016llx)\n",
					   (UINT64)MAX_PHYS_ADDR);
                Print(L"The entry above exceeds MAX_PHYS_ADDR (%016llx)\n",
					   (UINT64)MAX_PHYS_ADDR);
				error_flag = true;
			}
			HALT_ON_ERRORCOND(PhysEnd <= MAX_PHYS_ADDR);
		}
		printf("End UEFI GetMemoryMap result\n");
        Print(L"End UEFI GetMemoryMap result\n");

		HALT_ON_ERRORCOND(!error_flag && "MAX_PHYS_ADDR too small");
	}

	/* Free buffer */
	{
		FreePool(memory_map);
	}
}

/*
 * Open the root directory of the volume (e.g. FS0:).
 *
 * loaded_image: loaded image of this UEFI service.
 * Return opened root directory, no need to close.
 */
static EFI_FILE_HANDLE xmhf_efi_open_volume(EFI_LOADED_IMAGE *loaded_image)
{
	EFI_FILE_IO_INTERFACE *io_volume;
	EFI_FILE_HANDLE volume;

	/* ref: https://wiki.osdev.org/Loading_files_under_UEFI */
	UEFI_CALL(BS->HandleProtocol, 3, loaded_image->DeviceHandle,
			  &FileSystemProtocol, (void **)&io_volume);
	UEFI_CALL(io_volume->OpenVolume, 2, io_volume, &volume);

	return volume;
}

/*
 * Open configuration for XMHF.
 *
 * volume: root of the current file system.
 * loaded_image: loaded image of this UEFI service.
 * Return opened config file, need to close with EFI_FILE_HANDLE->Close().
 *
 * Looks like we cannot easily load an UEFI service with argc and argv.
 * Thus, we add ".conf" suffix to the pathname of the executable.
 * e.g. "\EFI\BOOT\init-x86-amd64.efi" -> "\EFI\BOOT\init-x86-amd64.efi.conf"
 */
static EFI_FILE_HANDLE xmhf_efi_open_config(EFI_FILE_HANDLE volume,
											EFI_LOADED_IMAGE *loaded_image)
{
	FILEPATH_DEVICE_PATH *fp = NULL;
	UINT16 fp_size = 0;
	UINT16 old_size = 0;
	UINT16 new_size = 0;
	UINT16 cur_size = 0;
	UINT16 index = 0;
	UINT16 *new_str = NULL;
	EFI_FILE_HANDLE file_handle;

	/* Get old file path */
	HALT_ON_ERRORCOND(loaded_image->DeviceHandle != NULL);
	HALT_ON_ERRORCOND(loaded_image->FilePath->Type == MEDIA_DEVICE_PATH);
	HALT_ON_ERRORCOND(loaded_image->FilePath->SubType == MEDIA_FILEPATH_DP);
	fp = (FILEPATH_DEVICE_PATH *)loaded_image->FilePath;
	fp_size = *(UINT16 *)fp->Header.Length;
	//Print(L"fp: %s\n", fp->PathName);

	/* Compute size */
	HALT_ON_ERRORCOND(fp_size > END_DEVICE_PATH_LENGTH);
	HALT_ON_ERRORCOND(fp_size % 2 == 0);
	old_size = fp_size - END_DEVICE_PATH_LENGTH;
	/* 10 == strlen(".conf") * sizeof(UINT16) */
	new_size = old_size + 10;
	/* Prevent overflow */
	HALT_ON_ERRORCOND(new_size > old_size);
	HALT_ON_ERRORCOND(old_size % 2 == 0);
	HALT_ON_ERRORCOND(old_size - 2 > 0);
	HALT_ON_ERRORCOND(new_size % 2 == 0);

	/* Allocate new file path */
	HALT_ON_ERRORCOND((new_str = AllocatePool(new_size)) != NULL);
	memcpy(new_str, fp->PathName, old_size);
	cur_size = old_size;
	index = cur_size / 2 - 1;
	for (char *i = ".conf"; *i != '\0'; i++) {
		HALT_ON_ERRORCOND(new_str[index] == 0);
		new_str[index] = (UINT16)(*i);
		index++;
		new_str[index] = 0;
		cur_size += sizeof(UINT16);
	}
	/* If cur_size > new_size, then buffer overflow */
	HALT_ON_ERRORCOND(cur_size == new_size);

	/* Open new file, ref: https://wiki.osdev.org/Loading_files_under_UEFI */
	UEFI_CALL(volume->Open, 5, volume, &file_handle, new_str,
			  EFI_FILE_MODE_READ,
			  EFI_FILE_READ_ONLY | EFI_FILE_HIDDEN | EFI_FILE_SYSTEM);

	/* Free new file path */
	FreePool(new_str);

	return file_handle;
}



/*
 * Read and parse config file.
 *
 * file_handle: opened file handle.
 * xmhf_efi_config: will be filled with config information.
 *                  After use, call FreePool on free_ptr.
 */
static void xmhf_efi_read_config(EFI_FILE_HANDLE file_handle,
								 xmhf_efi_config *config)
{
	UINT64 size;
	UINTN buf_size;
	char *buf;
	UINT64 read_size;
	UINT64 index;

	/* Prepare buffer */
	size = efi_file_get_size(file_handle);
	buf_size = size + 1;
	HALT_ON_ERRORCOND(buf_size > size);
	HALT_ON_ERRORCOND((buf = AllocatePool(buf_size)) != NULL);

	/* Read file */
	read_size = buf_size;
	UEFI_CALL(file_handle->Read, 3, file_handle, &read_size, buf);
	HALT_ON_ERRORCOND(read_size == size);

#define XMHF_EFI_READ_CONFIG_WHILE_LOOP() \
	do { \
		while (1) { \
			HALT_ON_ERRORCOND(index < buf_size); \
			if (buf[index] == '\n') { \
				buf[index] = '\0'; \
				index++; \
				break; \
			} else { \
				index++; \
			} \
		} \
	} while (0)

	/* First line of config file: command line */
	index = 0;
	config->free_ptr = buf;
	config->cmdline = buf + index;
	XMHF_EFI_READ_CONFIG_WHILE_LOOP();

	/* Second line of config file: runtime file */
	config->runtime_file = buf + index;
	XMHF_EFI_READ_CONFIG_WHILE_LOOP();

	/* Third line of config file: SINIT module */
	config->sinit_module = buf + index;
	XMHF_EFI_READ_CONFIG_WHILE_LOOP();

#undef XMHF_EFI_READ_CONFIG_WHILE_LOOP

	/* Make sure we are at EOF */
	HALT_ON_ERRORCOND(index == size);
}

/*
 * Load XMHF secure loader (SL) and runtime (RT) to memory.
 *
 * volume: root of the current file system.
 * pathname: pathname of file in UEFI to load SL+RT from.
 * efi_info: this function will set slrt_* fields.
 *
 * This function also allocates memory in UEFI to hide memory from guest.
 */
static void xmhf_efi_load_slrt(EFI_FILE_HANDLE volume, char *pathname,
							   xmhf_efi_info_t *efi_info)
{
	EFI_FILE_HANDLE file_handle;
	wchar_t *wpathname;
	UINT64 file_size;
	UINT64 buf_size;
	UINT64 read_size;
	UINT64 start;
	UINT64 end;
	UINT64 nonzero_end;
#ifdef __XMHF_PIE_RUNTIME__
	UINT64 relocation_offset;
#endif /* __XMHF_PIE_RUNTIME__ */

	/* Convert pathname to wchar_t */
	wpathname = xmhf_efi_bs2wcs(pathname);
	Print(L"SL+RT file name: %s\n", wpathname);

	/* Open new file, ref: https://wiki.osdev.org/Loading_files_under_UEFI */
	UEFI_CALL(volume->Open, 5, volume, &file_handle, wpathname,
			  EFI_FILE_MODE_READ,
			  EFI_FILE_READ_ONLY | EFI_FILE_HIDDEN | EFI_FILE_SYSTEM);

	/* Free converted pathname to wchar_t */
	FreePool(wpathname);

	/* Get file size */
	start = __TARGET_BASE_SL;
	file_size = efi_file_get_size(file_handle);
	nonzero_end = start + file_size;
	HALT_ON_ERRORCOND(nonzero_end > start);

	/* If Runtime bss is not in the file, read RPB to get runtime size */
#ifdef __SKIP_RUNTIME_BSS__
	{
		UINT64 read_rpb_size = sizeof(RPB);
		RPB rpb;

		/* Read RPB */
		UEFI_CALL(file_handle->SetPosition, 2, file_handle, PA_PAGE_SIZE_2M);
		UEFI_CALL(file_handle->Read, 3, file_handle, &read_rpb_size, &rpb);
		HALT_ON_ERRORCOND(read_rpb_size == sizeof(RPB));
		UEFI_CALL(file_handle->SetPosition, 2, file_handle, 0);

		/* Set end */
		HALT_ON_ERRORCOND(nonzero_end <= rpb.XtVmmRuntimeBssBegin);
		end = rpb.XtVmmRuntimeBssEnd;
	}
#else /* !__SKIP_RUNTIME_BSS__ */
	end = nonzero_end;
#endif /* __SKIP_RUNTIME_BSS__ */

	/* Compute buffer size (larger than file size, 4K aligned) */
	buf_size = PA_PAGE_ALIGN_UP_4K((end - start) + 1);
	HALT_ON_ERRORCOND(buf_size > (end - start));
#ifdef __XMHF_PIE_RUNTIME__
	/* Allocate 2M more to make sure SL is 2M aligned. */
	buf_size += PA_PAGE_SIZE_2M;
#endif /* __XMHF_PIE_RUNTIME__ */

	/* Allocate memory */
	{
		UINTN pages;
		EFI_PHYSICAL_ADDRESS addr;

		pages = buf_size >> PAGE_SHIFT_4K;
		HALT_ON_ERRORCOND((pages << PAGE_SHIFT_4K) == buf_size);
        Print(L"[<xmhf_efi_load_slrt> XMHF SL+RT memory size:0x%llX\n", buf_size);
#ifdef __XMHF_PIE_RUNTIME__
		addr = 0xFFFFF000ULL;
		UEFI_CALL(BS->AllocatePages, 4, AllocateMaxAddress,
				  EfiRuntimeServicesData, pages, &addr);

		/* Adjust for relocation due to PIE. */
		relocation_offset = PA_PAGE_ALIGN_UP_2M(addr - start);
		printf("relocation_offset: 0x%016llx\n", relocation_offset);
		start += relocation_offset;
		end += relocation_offset;

		/* Sanity check: [start, end) still in allocated memory. */
		HALT_ON_ERRORCOND(addr < addr + buf_size);
		HALT_ON_ERRORCOND(addr <= start);
		HALT_ON_ERRORCOND(start < end);
		HALT_ON_ERRORCOND(end <= addr + buf_size);
#else /* !__XMHF_PIE_RUNTIME__ */
		addr = start;
		UEFI_CALL(BS->AllocatePages, 4, AllocateAddress, EfiRuntimeServicesData,
				  pages, &addr);
		HALT_ON_ERRORCOND(addr == start);
#endif /* __XMHF_PIE_RUNTIME__ */
	}

	/* Copy file */
	HALT_ON_ERRORCOND((UINT64)(void *)start == start);
	read_size = buf_size;
	UEFI_CALL(file_handle->Read, 3, file_handle, &read_size, start);
	HALT_ON_ERRORCOND(read_size == file_size);

#ifdef __XMHF_PIE_RUNTIME__
	/* Pass relocation offset to SL and runtime */
	{
		RPB *rpb = (RPB *)(start + PA_PAGE_SIZE_2M);
		HALT_ON_ERRORCOND(rpb->XtVmmRelocationOffset == 0);
		rpb->XtVmmRelocationOffset = relocation_offset;
	}
#endif /* __XMHF_PIE_RUNTIME__ */

	/* Close file */
	UEFI_CALL(file_handle->Close, 1, file_handle);

	/* Set efi_info */
	efi_info->slrt_start = start;
	efi_info->slrt_end = end;
#ifdef __SKIP_RUNTIME_BSS__
	efi_info->slrt_nonzero_end = nonzero_end;
#endif /* __SKIP_RUNTIME_BSS__ */
}

#ifdef __DRT__
/*
 * Load SINIT module to memory.
 *
 * volume: root of the current file system.
 * pathname: pathname of file in UEFI to load SINIT module from.
 * efi_info: this function will set sinit_* fields.
 */
static void xmhf_efi_load_sinit(EFI_FILE_HANDLE volume, char *pathname,
								xmhf_efi_info_t *efi_info)
{
	EFI_FILE_HANDLE file_handle;
	wchar_t *wpathname;
	UINT64 file_size;
	UINT64 buf_size;
	UINT64 read_size;
	UINT64 start;
	UINT64 end;

	/* Convert pathname to wchar_t */
	wpathname = xmhf_efi_bs2wcs(pathname);
	Print(L"SINIT file name: %s\n", wpathname);

	/* Open new file, ref: https://wiki.osdev.org/Loading_files_under_UEFI */
	UEFI_CALL(volume->Open, 5, volume, &file_handle, wpathname,
			  EFI_FILE_MODE_READ,
			  EFI_FILE_READ_ONLY | EFI_FILE_HIDDEN | EFI_FILE_SYSTEM);

	/* Free converted pathname to wchar_t */
	FreePool(wpathname);

	/* Get file size */
	file_size = efi_file_get_size(file_handle);

	/* Compute buffer size (larger than file size, 4K aligned) */
	buf_size = PA_PAGE_ALIGN_UP_4K(file_size + 1);
	HALT_ON_ERRORCOND(buf_size > file_size);

	/* Allocate memory */
	{
		UINTN pages;
		EFI_PHYSICAL_ADDRESS addr = ADDR_4GB;

		pages = buf_size >> PAGE_SHIFT_4K;
		HALT_ON_ERRORCOND((pages << PAGE_SHIFT_4K) == buf_size);
		UEFI_CALL(BS->AllocatePages, 4, AllocateMaxAddress,
				  EfiRuntimeServicesData, pages, &addr);

		start = addr;
		end = start + file_size;
		HALT_ON_ERRORCOND(start < end);
	}

	/* Copy file */
	HALT_ON_ERRORCOND((UINT64)(void *)start == start);
	read_size = buf_size;
	UEFI_CALL(file_handle->Read, 3, file_handle, &read_size, start);
	HALT_ON_ERRORCOND(read_size == file_size);

	/* Close file */
	UEFI_CALL(file_handle->Close, 1, file_handle);

	/* Set efi_info */
	efi_info->sinit_start = start;
	efi_info->sinit_end = end;
}
#endif /* __DRT__ */

/*
 * Find RSDP from SystemTable.
 *
 * Return pointer to RSDP.
 */
static void *xmhf_efi_find_acpi_rsdp(void)
{
	EFI_GUID guid = ACPI_20_TABLE_GUID;
	for (UINTN i = 0; i < ST->NumberOfTableEntries; i++) {
		EFI_CONFIGURATION_TABLE *t = &ST->ConfigurationTable[i];
		if (CompareGuid(&guid, &t->VendorGuid) == 0) {
			return t->VendorTable;
		}
	}
	/* Require ACPI RSDP to be found */
	HALT_ON_ERRORCOND(0 && "ACPI RSDP not found");
}

/*
 * Store current CPU state to efi_info.
 *
 * efi_info: data structure to store state to.
 */
static void xmhf_efi_store_guest_state(xmhf_efi_info_t *efi_info)
{
	{
		uintptr_t eflags;
		get_eflags(eflags);
		efi_info->interrupt_enabled = !!(eflags & EFLAGS_IF);
		disable_intr();
	}
	efi_info->guest_ES_selector = read_segreg_es();
	efi_info->guest_CS_selector = read_segreg_cs();
	efi_info->guest_SS_selector = read_segreg_ss();
	efi_info->guest_DS_selector = read_segreg_ds();
	efi_info->guest_FS_selector = read_segreg_fs();
	efi_info->guest_GS_selector = read_segreg_gs();
	{
		uint16_t ldtr;
		asm volatile ("sldt %0" : "=g"(ldtr));
		efi_info->guest_LDTR_selector = ldtr;
	}
	{
		uint16_t tr;
		asm volatile ("str %0" : "=g"(tr));
		efi_info->guest_TR_selector = tr;
	}
	efi_info->guest_IA32_PAT = rdmsr64(MSR_IA32_PAT);
	efi_info->guest_IA32_EFER = rdmsr64(MSR_EFER);
	{
		/*
		 * Assume in 64-bit paging, so we ignore PDPTEs (because we are not in
		 * PAE paging).
		 */
		HALT_ON_ERRORCOND((efi_info->guest_IA32_EFER & (1U << EFER_LME)) &&
						  (read_cr0() & CR0_PG));
		efi_info->guest_PDPTE0 = 0;
		efi_info->guest_PDPTE1 = 0;
		efi_info->guest_PDPTE2 = 0;
		efi_info->guest_PDPTE3 = 0;
		/* In 64-bit paging, most segment registers have limit 0xffffffff. */
		efi_info->guest_ES_limit = 0xffffffff;
		efi_info->guest_CS_limit = 0xffffffff;
		efi_info->guest_SS_limit = 0xffffffff;
		efi_info->guest_DS_limit = 0xffffffff;
		efi_info->guest_FS_limit = 0xffffffff;
		efi_info->guest_GS_limit = 0xffffffff;
		/* Cannot easily get LDTR and TR limit, using value from QEMU/KVM. */
		efi_info->guest_LDTR_limit = 0x0000ffff;
		efi_info->guest_TR_limit = 0x0000ffff;
	}
	{
		struct {
			uint16_t limit;
			uintptr_t base;
		} __attribute__((packed)) gdtr;
		asm volatile ("sgdt %0" : "=m"(gdtr));
		efi_info->guest_GDTR_limit = gdtr.limit;
		efi_info->guest_GDTR_base = gdtr.base;
	}
	{
		struct {
			uint16_t limit;
			uintptr_t base;
		} __attribute__((packed)) idtr;
		asm volatile ("sidt %0" : "=m"(idtr));
		efi_info->guest_IDTR_limit = idtr.limit;
		efi_info->guest_IDTR_base = idtr.base;
	}
	{
		/*
		 * In 64-bit code, access rights are usually the same. Using QEMU/KVM
		 * value.
		 */
		efi_info->guest_ES_access_rights = 0xc093;
		efi_info->guest_CS_access_rights = 0xa09b;
		efi_info->guest_SS_access_rights = 0xc093;
		efi_info->guest_DS_access_rights = 0xc093;
		efi_info->guest_FS_access_rights = 0xc093;
		efi_info->guest_GS_access_rights = 0xc093;
	}
	{
		/* Using QEMU/KVM value. */
		efi_info->guest_LDTR_access_rights = 0x0082;
		efi_info->guest_TR_access_rights = 0x008b;
	}
	efi_info->guest_SYSENTER_CS = rdmsr64(IA32_SYSENTER_CS_MSR);
	efi_info->guest_CR0 = read_cr0();
	efi_info->guest_CR3 = read_cr3();
	efi_info->guest_CR4 = read_cr4();
	efi_info->guest_ES_base = 0;
	efi_info->guest_CS_base = 0;
	efi_info->guest_SS_base = 0;
	efi_info->guest_DS_base = 0;
	efi_info->guest_FS_base = rdmsr64(IA32_MSR_FS_BASE);
	efi_info->guest_GS_base = rdmsr64(IA32_MSR_GS_BASE);
	{
		/* Using QEMU/KVM value. */
		efi_info->guest_TR_base = 0;
		efi_info->guest_LDTR_base = 0;
	}
	/* guest_GDTR_base and guest_IDTR_base are already set above. */
	{
		uintptr_t dr7;
		asm volatile("mov %%dr7, %0" : "=r"(dr7));
		efi_info->guest_DR7 = dr7;
	}
	/* guest_RSP, guest_RIP, and guest_RFLAGS are set later. */
	efi_info->guest_SYSENTER_ESP = rdmsr64(IA32_SYSENTER_ESP_MSR);
	efi_info->guest_SYSENTER_EIP = rdmsr64(IA32_SYSENTER_EIP_MSR);
}

/*
 * Refresh CPU state in efi_info to current CPU.
 *
 * efi_info: data structure that contains state.
 */
static void xmhf_efi_refresh_guest_state(xmhf_efi_info_t *efi_info)
{
	/* Check presence of XMHF. */
	{
		u32 eax, ebx, ecx, edx;
		printf("Detecting XMHF ...\n");
		cpuid(0x46484d58U, &eax, &ebx, &ecx, &edx);
		if (eax == 0x46484d58U) {
			printf("XMHF detected: %08x %08x %08x %08x\n", eax, ebx, ecx, edx);
		} else {
			HALT_ON_ERRORCOND(0 && "XMHF not detected");
		}
	}

	/* Reload LDTR */
	{
		uint16_t ldtr = efi_info->guest_LDTR_selector;
		printf("Reloading LDT ...\n");
		asm volatile ("lldt %0" : : "g"(ldtr));
		printf("Reloaded LDT\n");
	}

	/*
	 * Cannot reload TR easily. During the first time loading TR, the hardware
	 * will set TSSsegmentDescriptor(busy) := 1. The second time loading TR
	 * will cause #GP(selector). A possible way to do this in the future is to
	 * clear the TSSsegmentDescriptor(busy) bit, then reload TR.
	 */
	if (1) {
		printf("Warning: not reloading TR. May cause compatibility bugs if "
			   "UEFI firmware uses TR.\n");
	} else {
		uint16_t tr = efi_info->guest_TR_selector;
		printf("Reloading TR ...\n");
		asm volatile ("ltr %0" : : "g"(tr));
		printf("Reloaded TR\n");
	}

	/* Enable interrupts if needed. */
	if (efi_info->interrupt_enabled) {
		enable_intr();
	}
}

/* Main function for UEFI service, follow https://wiki.osdev.org/GNU-EFI */
EFI_STATUS
EFIAPI
efi_main (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
	xmhf_efi_config config;
	xmhf_efi_info_t efi_info = {};
	EFI_LOADED_IMAGE *loaded_image = NULL;
	EFI_FILE_HANDLE volume = NULL;

	InitializeLib(ImageHandle, SystemTable);

#if defined(__DEBUG_SERIAL__)
    {
        // initialize debugging early on
	    xmhf_debug_init((char *)&g_uart_config);
    }
#endif // __DEBUG_SERIAL__
    // dbg_x86_uart_pci_init(NULL);

	Print(L"Hello, world from console!\n");
	printf("Hello, world from serial!\n");

	/* https://wiki.osdev.org/Debugging_UEFI_applications_with_GDB */
	UEFI_CALL(BS->HandleProtocol, 3, ImageHandle, &LoadedImageProtocol,
			  (void **)&loaded_image);

	/* For debugging using GDB */
	Print(L"Image base: 0x%lx\n", loaded_image->ImageBase);

	/* Check maximum physical memory */
	{
		xmhf_efi_check_max_phys_mem();
	}

	/* Read command line arguments from file */
	{
		EFI_FILE_HANDLE conf;

		volume = xmhf_efi_open_volume(loaded_image);
		conf = xmhf_efi_open_config(volume, loaded_image);
		xmhf_efi_read_config(conf, &config);
		UEFI_CALL(conf->Close, 1, conf);
		efi_info.cmdline = config.cmdline;
	}

	/* Load XMHF secure loader and runtime */
	{
		xmhf_efi_load_slrt(volume, config.runtime_file, &efi_info);
	}

	/* Load SINIT module */
	{
#ifdef __DRT__
		xmhf_efi_load_sinit(volume, config.sinit_module, &efi_info);
#else /* !__DRT__ */
		efi_info.sinit_start = 0;
		efi_info.sinit_end = 0;
#endif /* __DRT__ */
	}

	/* Find ACPI RSDP */
	{
		efi_info.acpi_rsdp = (uintptr_t)xmhf_efi_find_acpi_rsdp();
	}

	/* Store guest state */
	{
		xmhf_efi_store_guest_state(&efi_info);
	}

	/* Call XMHF init */
	{
		efi2init(&efi_info, &efi_info.guest_RSP, &efi_info.guest_RIP,
				 &efi_info.guest_RFLAGS);
	}

	/* Load guest state */
	{
		xmhf_efi_refresh_guest_state(&efi_info);
	}

    // Measure OS bootloader
    // [TODO][Issue 141] In BIOS mode (not UEFI), Measure OS bootloader to PCR 7.
    {
        EFI_FILE_HANDLE volume = NULL;
        CHAR16* os_bootloader_filepath = NULL;

        volume = efi_os_bootloader_find(&os_bootloader_filepath);
        if(volume)
        {
            int ret = 0;

#define EFI_OS_BOOTLOADER_MEASURE_EXTEND_LOCALITY   (0)
#define EFI_OS_BOOTLOADER_MEASURE_EXTEND_PCR        (7)

            ret = efi_file_measure_and_extend_in_tpm(volume, os_bootloader_filepath, EFI_OS_BOOTLOADER_MEASURE_EXTEND_LOCALITY, EFI_OS_BOOTLOADER_MEASURE_EXTEND_PCR);
            if(!ret)
            {
                Print(L"Measured OS bootloader: %s\n", os_bootloader_filepath);
            }
        }
    }

	/* Clean up */
	{
		FreePool(config.free_ptr);
	}

	return EFI_SUCCESS;
}

