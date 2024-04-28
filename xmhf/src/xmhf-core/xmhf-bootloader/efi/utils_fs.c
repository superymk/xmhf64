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

/// @brief EFI file system util functions.

#include "header.h"
#include "../hash/hash.h"

/// @brief Return true iff xmhf-bootloader can use the physical TPM device (either TPM 1.2 or TPM 2.0).
/// @param out_tpm 
/// @param out_tpm_fp 
/// @return 
static bool _is_tpm_present(struct tpm_if **out_tpm, struct tpm_if_fp **out_tpm_fp)
{
    struct tpm_if *tpm = get_tpm();
    struct tpm_if_fp *tpm_fp = NULL;

    if(!tpm)
    {
        printf("xmhf-bootloader: Failed to get <tpm>!\n");
        return false;
    }

    if(!tpm_detect())
    {
        printf("xmhf-bootloader: Failed to get TPM version!\n");
        return false;
    }

    tpm_fp = (struct tpm_if_fp *)get_tpm_fp();
    if(!tpm_fp)
    {
        printf("xmhf-bootloader: Failed to get <tpm_fp>!\n");
        return false;
    }

    // Check TPM versions
    if((tpm->major != TPM12_VER_MAJOR) && (tpm->major != TPM20_VER_MAJOR))
    {
        printf("xmhf-bootloader: Unknown TPM version!\n");
        return false;
    }

    // On success
    *out_tpm = tpm;
    *out_tpm_fp = tpm_fp;
    return true;
}

static int efi_tpm_measure_and_extend_mem(int locality, int pcr, uint8_t* mem, size_t mem_size)
{
    struct tpm_if *tpm = NULL;
    struct tpm_if_fp *tpm_fp = NULL;
    bool found_tpm = false;
    union sha_digest digest = {0};
    int result = 0;

    // Check: Valid <locality> and <pcr> for physical TPM devices.
    if((pcr < 0) || (pcr >= 24))
        return -1;
    if((locality < 0) || (locality > 4))
        return -1;

    found_tpm = _is_tpm_present(&tpm, &tpm_fp);
    if(!found_tpm)
        return -1;


    // Measure memory
    if(tpm->major == TPM12_VER_MAJOR)
    {
        result = sha1_mem(mem, mem_size, digest.sha1_digest);
        if(result)
        {
            printf("xmhf-bootloader: Measure memory (addr: 0x%lX, size: 0x%lX) with SHA1 error!\n", (uintptr_t)mem, mem_size);
            HALT();
        }
    }
    else if(tpm->major == TPM20_VER_MAJOR)
    {
        result = sha2_256_mem(mem, mem_size, digest.sha2_256_digest);
        if(result)
        {
            printf("xmhf-bootloader: Measure memory (addr: 0x%lX, size: 0x%lX) with SHA256 error!\n", (uintptr_t)mem, mem_size);
            HALT();
        }
    }
    // No need to check invalid <tpm->major> again, because we have checked it.

    if(tpm->major == TPM12_VER_MAJOR)
    {
        hash_list_t hl;

        hl.count = 1;
        hl.entries[0].alg = TB_HALG_SHA1;
        memcpy(&hl.entries[0].hash.sha1, digest.sha1_digest, SHA1_DIGEST_LENGTH);

        result = tpm_fp->pcr_extend(tpm, locality, pcr, &hl);
        if(!result)
        {
            printf("xmhf-bootloader (TPM1.2): Extend memory (addr: 0x%lX, size: 0x%lX) to PCR7 error!\n", (uintptr_t)mem, mem_size);
            return -1;
        }
    }
    else if(tpm->major == TPM20_VER_MAJOR)
    {
        hash_list_t hl;

        hl.count = 1;
        hl.entries[0].alg = TB_HALG_SHA256;
        memcpy(&hl.entries[0].hash.sha256, digest.sha2_256_digest, SHA256_DIGEST_LENGTH);

        result = tpm_fp->pcr_extend(tpm, locality, pcr, &hl);
        if(!result)
        {
            printf("xmhf-bootloader (TPM2): Extend memory (addr: 0x%lX, size: 0x%lX) to PCR7 error!\n", (uintptr_t)mem, mem_size);
            return -1;
        }
    }

    // On success
    return 0;

}

int efi_file_measure_and_extend_in_tpm(EFI_FILE_HANDLE volume, CHAR16* filepath, int tpm_locality, int tpm_pcr)
{
    int status = 0;
    EFI_FILE_HANDLE file_handle;
    UINT64 file_size;
    uint8_t *buf = NULL;

    /* Open new file, ref: https://wiki.osdev.org/Loading_files_under_UEFI */
	UEFI_CALL(volume->Open, 5, volume, &file_handle, filepath,
			  EFI_FILE_MODE_READ,
			  EFI_FILE_READ_ONLY | EFI_FILE_HIDDEN | EFI_FILE_SYSTEM);
    if(!file_handle)
    {
        status = -1;
        goto out;
    }

    // Get file size
    file_size = efi_file_get_size(file_handle);
	buf = AllocatePool(file_size);
    if(!buf)
    {
        status = -1;
        goto out;
    }

    // Read all file contents
	UEFI_CALL(file_handle->Read, 3, file_handle, &file_size, buf);

    // Measure 
    status = efi_tpm_measure_and_extend_mem(tpm_locality, tpm_pcr, buf, file_size);
    if(status)
    {
        goto out;
    }

    // On success
    status = 0;

out:
    // Close file
    if(file_handle)
        UEFI_CALL(file_handle->Close, 1, file_handle);
    if(buf)
        FreePool(buf);
    return status;
}

UINT64 efi_file_get_size(EFI_FILE_HANDLE file_handle)
{
	UINTN size = 0;
	EFI_FILE_INFO *info = NULL;
	UINT64 ans = 0;

	/* Get buffer size */
	{
		EFI_STATUS status;
		status = uefi_call_wrapper(file_handle->GetInfo, 4, file_handle,
								   &GenericFileInfo, &size, info);
		HALT_ON_ERRORCOND(status == EFI_BUFFER_TOO_SMALL);
	}

	/* Allocate buffer */
	HALT_ON_ERRORCOND((info = AllocatePool(size)) != NULL);

	/* Get buffer */
	UEFI_CALL(file_handle->GetInfo, 4, file_handle, &GenericFileInfo, &size,
			  info);

	/* Record ans */
	ans = info->FileSize;

	/* Free buffer */
	FreePool(info);

	return ans;
}

