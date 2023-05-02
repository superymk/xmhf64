#include <efi.h>
#include <efilib.h>
#include <wchar.h>
#include <stdio.h>
#include <string.h>
#include "xmhf_efi.h"

/* HALT() contains an infinite loop to indicate that it never exits */
#define HALT() do { __asm__ __volatile__ ("hlt\r\n"); } while (1)

#define XMHF_ASSERT(expr) \
	do { \
		if (!(expr)) { \
			printf("XMHF_ASSERT(%s) failed at %s:%d\n", #expr, __FILE__, \
				   __LINE__); \
			HALT(); \
		} \
	} while(0)

#define UEFI_CALL(...) \
	do { \
		EFI_STATUS _status; \
		_status = uefi_call_wrapper(__VA_ARGS__); \
		if (EFI_ERROR(_status)) { \
			printf("UEFI_CALL(%s) error at %s:%d (status = 0x%08lx)\n", \
				   #__VA_ARGS__, __FILE__, __LINE__, _status); \
			Print(L"UEFI_CALL returns EFI_STATUS: %r\n", _status); \
			HALT(); \
		} \
	} while(0)

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
 * Open the root directory of the volume (e.g. FS0:).
 *
 * loaded_image: loaded image of this UEFI service.
 * Return opened root directory, no need to close.
 */
EFI_FILE_HANDLE xmhf_efi_open_volume(EFI_LOADED_IMAGE *loaded_image)
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
 * loaded_image: loaded image of this UEFI service.
 * Return opened config file, need to close with EFI_FILE_HANDLE->Close().
 *
 * Looks like we cannot easily load an UEFI service with argc and argv.
 * Thus, we add ".conf" suffix to the pathname of the executable.
 * e.g. "\EFI\BOOT\init-x86-amd64.efi" -> "\EFI\BOOT\init-x86-amd64.efi.conf"
 */
EFI_FILE_HANDLE xmhf_efi_open_config(EFI_FILE_HANDLE volume,
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
	XMHF_ASSERT(loaded_image->DeviceHandle != NULL);
	XMHF_ASSERT(loaded_image->FilePath->Type == MEDIA_DEVICE_PATH);
	XMHF_ASSERT(loaded_image->FilePath->SubType == MEDIA_FILEPATH_DP);
	fp = (FILEPATH_DEVICE_PATH *)loaded_image->FilePath;
	fp_size = *(UINT16 *)fp->Header.Length;
	//Print(L"fp: %s\n", fp->PathName);

	/* Compute size */
	XMHF_ASSERT(fp_size > END_DEVICE_PATH_LENGTH);
	XMHF_ASSERT(fp_size % 2 == 0);
	old_size = fp_size - END_DEVICE_PATH_LENGTH;
	/* 10 == strlen(".conf") * sizeof(UINT16) */
	new_size = old_size + 10;
	/* Prevent overflow */
	XMHF_ASSERT(new_size > old_size);
	XMHF_ASSERT(old_size % 2 == 0);
	XMHF_ASSERT(old_size - 2 > 0);
	XMHF_ASSERT(new_size % 2 == 0);

	/* Allocate new file path */
	XMHF_ASSERT((new_str = AllocatePool(new_size)) != NULL);
	memcpy(new_str, fp->PathName, old_size);
	cur_size = old_size;
	index = cur_size / 2 - 1;
	for (char *i = ".conf"; *i != '\0'; i++) {
		XMHF_ASSERT(new_str[index] == 0);
		new_str[index] = (UINT16)(*i);
		index++;
		new_str[index] = 0;
		cur_size += sizeof(UINT16);
	}
	/* If cur_size > new_size, then buffer overflow */
	XMHF_ASSERT(cur_size == new_size);

	/* Open new file, ref: https://wiki.osdev.org/Loading_files_under_UEFI */
	UEFI_CALL(volume->Open, 5, volume, &file_handle, new_str,
			  EFI_FILE_MODE_READ,
			  EFI_FILE_READ_ONLY | EFI_FILE_HIDDEN | EFI_FILE_SYSTEM);

	/* Free new file path */
	FreePool(new_str);

	return file_handle;
}

/*
 * Return size of opened file.
 *
 * file_handle: opened file handle.
 * Return size of file.
 */
UINT64 xmhf_efi_get_file_size(EFI_FILE_HANDLE file_handle)
{
	UINTN size = 0;
	EFI_FILE_INFO *info = NULL;
	UINT64 ans = 0;

	/* Get buffer size */
	{
		EFI_STATUS status;
		status = uefi_call_wrapper(file_handle->GetInfo, 4, file_handle,
								   &GenericFileInfo, &size, info);
		XMHF_ASSERT(status == EFI_BUFFER_TOO_SMALL);
	}

	/* Allocate buffer */
	XMHF_ASSERT((info = AllocatePool(size)) != NULL);

	/* Get buffer */
	UEFI_CALL(file_handle->GetInfo, 4, file_handle, &GenericFileInfo, &size,
			  info);

	/* Record ans */
	ans = info->FileSize;

	/* Free buffer */
	FreePool(info);

	return ans;
}

/*
 * Read and parse config file.
 *
 * file_handle: opened file handle.
 * xmhf_efi_config: will be filled with config information.
 *                  After use, call FreePool on free_ptr.
 */
void xmhf_efi_read_config(EFI_FILE_HANDLE file_handle, xmhf_efi_config *config)
{
	UINT64 size;
	UINTN buf_size;
	char *buf;
	UINT64 read_size;
	UINT64 index;

	/* Prepare buffer */
	size = xmhf_efi_get_file_size(file_handle);
	buf_size = size + 1;
	XMHF_ASSERT(buf_size > size);
	XMHF_ASSERT((buf = AllocatePool(buf_size)) != NULL);

	/* Read file */
	read_size = buf_size;
	UEFI_CALL(file_handle->Read, 3, file_handle, &read_size, buf);
	XMHF_ASSERT(read_size == size);

#define XMHF_EFI_READ_CONFIG_WHILE_LOOP() \
	do { \
		while (1) { \
			XMHF_ASSERT(index < buf_size); \
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
	XMHF_ASSERT(index == size);
}

/*
 * Find RDSP from SystemTable.
 *
 * Return pointer to RDSP.
 */
void *xmhf_efi_find_acpi_rdsp(void)
{
	EFI_GUID guid = ACPI_20_TABLE_GUID;
	for (UINTN i = 0; i < ST->NumberOfTableEntries; i++) {
		EFI_CONFIGURATION_TABLE *t = &ST->ConfigurationTable[i];
		if (CompareGuid(&guid, &t->VendorGuid) == 0) {
			return t->VendorTable;
		}
	}
	/* Require ACPI RDSP to be found */
	XMHF_ASSERT(0 && "ACPI RDSP not found");
}

/* Main function for UEFI service, follow https://wiki.osdev.org/GNU-EFI */
EFI_STATUS
EFIAPI
efi_main (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
	xmhf_efi_config config;
	xmhf_efi_info_t efi_info = {};
	EFI_LOADED_IMAGE *loaded_image = NULL;

	InitializeLib(ImageHandle, SystemTable);

	Print(L"Hello, world from console!\n");
	printf("Hello, world from serial!\n");

	/* https://wiki.osdev.org/Debugging_UEFI_applications_with_GDB */
	UEFI_CALL(BS->HandleProtocol, 3, ImageHandle, &LoadedImageProtocol,
			  (void **)&loaded_image);

	/* For debugging using GDB */
	Print(L"Image base: 0x%lx\n", loaded_image->ImageBase);

	/* Read command line arguments from file */
	{
		EFI_FILE_HANDLE volume = xmhf_efi_open_volume(loaded_image);
		EFI_FILE_HANDLE conf = xmhf_efi_open_config(volume, loaded_image);
		xmhf_efi_read_config(conf, &config);
		efi_info.cmdline = config.cmdline;
	}

	/* Load XMHF secure loader and runtime */
	{
		// TODO
		// efi_info.rt_start = __TARGET_BASE_SL;
		// efi_info.rt_end = __TARGET_BASE_SL;
	}

	/* Find ACPI RDSP */
	{
		efi_info.acpi_rsdp = (uintptr_t)xmhf_efi_find_acpi_rdsp();
	}

	/* Allocate memory */
	{
		EFI_PHYSICAL_ADDRESS addr = 0x10000000;
		UEFI_CALL(BS->AllocatePages, 4, AllocateAddress, EfiRuntimeServicesData,
				  32768, &addr);
		Print(L"Allocated: %p\n", addr);
	}

	/* Call XMHF init */
	{
		cstartup(&efi_info);
	}

	/* Clean up */
	{
		FreePool(config.free_ptr);
	}

	return EFI_SUCCESS;
}

