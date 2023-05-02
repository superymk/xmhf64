#include <stdint.h>

typedef struct {
	/* Command line */
	char *cmdline;
	/* Start and end of XMHF runtime */
	uint64_t rt_start;
	uint64_t rt_end;
	/* Start and end of SINIT module. Not exist if both 0. */
	uint64_t sinit_start;
	uint64_t sinit_end;
	/* ACPI RSDP location */
	uint64_t acpi_rsdp;
} xmhf_efi_info_t;

extern void cstartup(xmhf_efi_info_t *xei);

