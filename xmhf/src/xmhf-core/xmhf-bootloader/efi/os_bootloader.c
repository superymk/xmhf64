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

// author: Miao Yu (superymk@cmu.edu)

#include "header.h"

#define NUM_OS_BOOTLOADERS (8)
static CHAR16 *_os_bootloader_sequence[NUM_OS_BOOTLOADERS] =
{
    L"\\EFI\\ubuntu\\shimx64.efi",
    L"\\EFI\\ubuntu\\grubx64.efi",
    L"\\EFI\\debian\\grubx64.efi",
    L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi",
    L"\\EFI\\BOOT\\BOOTX64.EFI"
};

EFI_FILE_HANDLE efi_os_bootloader_find(CHAR16 **out_os_bootloader_filepath)
{
    // EFI_STATUS Status;
    EFI_HANDLE *Handles;
    UINTN HandleCount;
    UINTN HandleIndex;
    UINTN j = 0;
    // EFI_DEVICE_PATH_PROTOCOL *FilePath;
    EFI_FILE_IO_INTERFACE *io_volume;
    EFI_FILE_HANDLE volume;
    bool found = false;

    UEFI_CALL(BS->LocateHandleBuffer, 5, ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &HandleCount, &Handles);
    // error handling

    for (HandleIndex = 0; HandleIndex < HandleCount; HandleIndex++)
    {
        // Open each volume
        /* ref: https://wiki.osdev.org/Loading_files_under_UEFI */
        UEFI_CALL(BS->HandleProtocol, 3, Handles[HandleIndex],
                    &FileSystemProtocol, (void **)&io_volume);
        UEFI_CALL(io_volume->OpenVolume, 2, io_volume, &volume);

        // Find OS bootloaders
        for (j = 0; j < NUM_OS_BOOTLOADERS; j++)
        {
            EFI_STATUS _status = EFI_SUCCESS;
            EFI_FILE_HANDLE file_handle = NULL;

            //// Ignore EFI API status, because bootloaders in <_os_bootloader_sequence> may not exist.
            _status = uefi_call_wrapper(volume->Open, 5, volume, &file_handle, _os_bootloader_sequence[j],
                        EFI_FILE_MODE_READ,
                        EFI_FILE_READ_ONLY | EFI_FILE_HIDDEN | EFI_FILE_SYSTEM);
            if (EFI_ERROR(_status))
            {
                if((_status & EFI_INVALID_PARAMETER) || (_status & EFI_NOT_FOUND))
                {
                    // File not found, do nothing.
                }
                else
                {
                    printf("UEFI_CALL error at %s:%d (status = 0x%08lx)\n", __FILE__, __LINE__, _status); 
                }
            }

            if (file_handle)
            {
                UEFI_CALL(file_handle->Close, 1, file_handle);
                found = true;
                break;
            }
        }

        if(found)
            break;
    }

    if (found)
    {
        *out_os_bootloader_filepath = _os_bootloader_sequence[j];
        Print(L"xmhf-bootloader: Found OS bootloader: %s on FS%d\n", *out_os_bootloader_filepath, HandleIndex);
        return volume;
    }

    return NULL;
}