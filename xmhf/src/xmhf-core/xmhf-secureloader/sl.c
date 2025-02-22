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

//sl.c
//secure loader implementation
// [Load PIE-enabled runtime] Use relocation sections, see https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-54839.html
//author: amit vasudevan (amitvasudevan@acm.org)
//author: Eric Li (xiaoyili@andrew.cmu.edu) for loading runtime compiled with Position Independent Executable (PIE)

#include <xmhf.h>
#include "sl-config.h"
#include "./hash/hash.h"
#include "tpm_measure.h"

RPB * rpb;
u32 sl_baseaddr=0;

//this is the SL parameter block and is placed in a seperate UNTRUSTED
//section. It is populated by the "init" (late or early) loader, which
//uses the late-launch mechanism to load the SL
struct _sl_parameter_block slpb __attribute__(( section(".sl_untrusted_params") )) = {
	.magic = SL_PARAMETER_BLOCK_MAGIC,
};

#ifdef __SKIP_RUNTIME_BSS__
/*
 * When the binary only contains non-bss portion of XMHF runtime, clear the
 * .bss portion of XMHF runtime to zero.
 */
static void xmhf_sl_clear_rt_bss(void)
{
	uintptr_t rt_bss_phys_begin, rt_bss_size;

#ifdef __DRT__
#ifdef __UEFI__
	/*
	 * In UEFI booting, decompressing gzip runtime binary requires
	 * additional code. Not compressing runtime binary will result in
	 * large amount of space wasted in EFI partition. Thus, we allow
	 * __SKIP_RUNTIME_BSS__ to decrease size of runtime binary.
	 */
	printf("Warning: __SKIP_RUNTIME_BSS__ not recommended when __DRT__.\n");
	printf("This changes the trusted booting design of XMHF SL+RT.\n");
#else /* !__UEFI__ */
	/*
	 * In BIOS booting, GRUB can easily decompress gzip runtime binary.
	 * So we disallow __SKIP_RUNTIME_BSS__ for now.
	 */
	#error "__SKIP_RUNTIME_BSS__ not supported when __DRT__"
#endif /* __UEFI__ */
#endif /* __DRT__ */

#ifdef __XMHF_PIE_RUNTIME__
	rt_bss_phys_begin = rpb->XtVmmRuntimeBssBegin - rpb->XtVmmRelocationOffset - __TARGET_BASE_SL;
#else /* !__XMHF_PIE_RUNTIME__ */
	rt_bss_phys_begin = rpb->XtVmmRuntimeBssBegin - __TARGET_BASE_SL;
#endif /* __XMHF_PIE_RUNTIME__ */
	rt_bss_size = rpb->XtVmmRuntimeBssEnd - rpb->XtVmmRuntimeBssBegin;
	//memset((void *)(uintptr_t)rt_bss_phys_begin, 0, rt_bss_size);
	asm volatile ("cld; rep stosb;" : : "a" (0), "c" (rt_bss_size),
				  "D" (rt_bss_phys_begin) : "memory", "cc");
}
#endif /* __SKIP_RUNTIME_BSS__ */

#ifdef __XMHF_PIE_RUNTIME__
#if !defined(__UEFI__) || !defined(__AMD64__)
#error Currently runtime PIE only supported in 64-bit UEFI.
#endif

/* https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-54839.html */
typedef struct {
	u64 r_offset;
	u64 r_info;
	u64 r_addend;
} rela_t;

/*
 * Handle runtime's .rela.dyn section.
 */
static void xmhf_sl_handle_rt_rela_dyn(void)
{
	hva_t offset = rpb->XtVmmRelocationOffset;
	sla_t begin = (hva_t)hva2sla((void *)(rpb->XtVmmRuntimeRelaDynBegin + offset));
	sla_t end = (hva_t)hva2sla((void *)(rpb->XtVmmRuntimeRelaDynEnd + offset));

	HALT_ON_ERRORCOND(begin < end);
	HALT_ON_ERRORCOND((end - begin) % 24 == 0);

	for (hva_t i = begin; i < end; i += 24) {
		rela_t *rela = (rela_t *)i;
		/* Address to write to. */
		u64 *p = (u64 *)((sla_t)hva2sla((void *)rela->r_offset) + offset);
		/* Type is always 8, probably R_AMD64_RELATIVE. */
		HALT_ON_ERRORCOND(rela->r_info == 8ULL);
		/* Current value should match r_addend. */
		HALT_ON_ERRORCOND(*p == rela->r_addend);
		/* Modify value. */
		*p += offset;
	}
}
#endif /* __XMHF_PIE_RUNTIME__ */

// Returns true if add does not overflow.
static inline bool safe_add(uint64_t *out, uint64_t op1, uint64_t op2)
{
	if (op1 <= UINT64_MAX - op2) {
		*out = op1 + op2;
		return true;
	} else {
		return false;
	}
}

// [TODO][Issue 149] Double check the definitions of address regions: representing with a pair of (base, size) is better 
// than (base, end) because <end> may overflow to 0.
/// @brief 
/// @param v1 
/// @param sz1 
/// @param v2 
/// @param sz2 
/// @return Return 0 if the two memory regions do not overlap.
///         Return 1 if overlap.
///         Return -1 if a memory region is invalid (i.e., no size or overflow).
static inline int MEM_REGION_OVERLAP(uint64_t v1, uint64_t sz1, uint64_t v2, uint64_t sz2)
{
	uint64_t base1 = v1;
	uint64_t end1;
	uint64_t base2 = v2;
	uint64_t end2;

	if (sz1 == 0 || sz2 == 0) {
		return -1;
	}
	
	if (!safe_add(&end1, base1, sz1 - 1)) {
		return -1;
	}

	if (!safe_add(&end2, base2, sz2 - 1)) {
		return -1;
	}

	if(base1 <= end2 && base2 <= end1)
        return 1;
    else
        return 0;
}

//we get here from sl-*-entry.S
// rdtsc_* are valid only if PERF_CRIT is not defined.  slheader.S
// sets them to 0 otherwise.
void xmhf_sl_main(u32 cpu_vendor, u32 baseaddr, u32 rdtsc_eax, u32 rdtsc_edx)
{
	u32 runtime_physical_base;
	u32 runtime_size_2Maligned;

#ifdef __AMD64__
	xmhf_setup_sl_paging(baseaddr);
#elif !defined(__I386__)
    #error "Unsupported Arch"
#endif /* !defined(__I386__) */

	//linker relocates sl image starting from 0, so
    //parameter block must be at offset <SL_LOW_CODE_DATA_SECTION_SIZE>
	HALT_ON_ERRORCOND( (sla_t)&slpb == SL_LOW_CODE_DATA_SECTION_SIZE );

	//do we have the required MAGIC?
	HALT_ON_ERRORCOND( slpb.magic == SL_PARAMETER_BLOCK_MAGIC);

	//we currently only support x86 (AMD and Intel)
	HALT_ON_ERRORCOND (cpu_vendor == CPU_VENDOR_AMD || cpu_vendor == CPU_VENDOR_INTEL);

	//Set global variable g_uefi_rsdp, or
	//xmhf_baseplatform_arch_x86_acpi_getRSDP() cannot find ACPI RSDP.
	g_uefi_rsdp = slpb.uefi_acpi_rsdp;

	//initialize debugging early on
	xmhf_debug_init((char *)&slpb.uart_config);

	//initialze sl_baseaddr variable and print its value out
	sl_baseaddr = baseaddr;

	//is our launch before the OS has been loaded (early) is loaded or
	//is it after the OS has been loaded (late)
	if(slpb.isEarlyInit)
		printf("SL(early-init): at 0x%08x, starting...\n", sl_baseaddr);
    else
		printf("SL(late-init): at 0x%08x, starting...\n", sl_baseaddr);

	//debug: dump SL parameter block
	printf("SL: slpb at = 0x%08lx\n", (sla_t)&slpb);
	printf("	errorHandler=0x%08x\n", slpb.errorHandler);
	printf("	isEarlyInit=0x%08x\n", slpb.isEarlyInit);
	printf("	numE820Entries=%u\n", slpb.numE820Entries);
	printf("	system memory map buffer at 0x%08lx\n", (sla_t)&slpb.memmapbuffer);
	printf("	numCPUEntries=%u\n", slpb.numCPUEntries);
	printf("	cpuinfo buffer at 0x%08lx\n", (sla_t)&slpb.cpuinfobuffer);
	printf("	runtime size= %u bytes\n", slpb.runtime_size);
	printf("	OS bootmodule at 0x%08x, size=%u bytes\n",
		slpb.runtime_osbootmodule_base, slpb.runtime_osbootmodule_size);
    printf("  OS boot_drive is 0x%02x\n", (u32)slpb.runtime_osbootdrive);
    printf("\tcmdline = \"%s\"\n", slpb.cmdline);

	//debug: if we are doing some performance measurements
    slpb.rdtsc_after_drtm = (u64)rdtsc_eax | ((u64)rdtsc_edx << 32);
    printf("SL: RDTSC before_drtm 0x%llx, after_drtm 0x%llx\n",
           slpb.rdtsc_before_drtm, slpb.rdtsc_after_drtm);
    printf("SL: [PERF] RDTSC DRTM elapsed cycles: 0x%llx\n",
           slpb.rdtsc_after_drtm - slpb.rdtsc_before_drtm);

	//get runtime physical base
	runtime_physical_base = sl_baseaddr + PAGE_SIZE_2M;	//base of SL + 2M

	//compute 2M aligned runtime size
	runtime_size_2Maligned = PAGE_ALIGN_UP_2M((ulong_t)slpb.runtime_size);

	printf("SL: runtime at 0x%08x; size=0x%08x bytes adjusted to 0x%08x bytes (2M aligned)\n",
			runtime_physical_base, slpb.runtime_size, runtime_size_2Maligned);

	//setup runtime parameter block with required parameters
	{
	#ifndef __XMHF_VERIFICATION__
		//get a pointer to the runtime header and make sure its sane
		rpb=(RPB *)PAGE_SIZE_2M;	//runtime starts at offset 2M from sl base
	#else
		//setup runtime parameter block pointer
		//actual definitions
		extern RPB _xrpb;
		rpb = (RPB *)&_xrpb;
	#endif

		printf("SL: RPB, magic=0x%08x\n", rpb->magic);
		HALT_ON_ERRORCOND(rpb->magic == RUNTIME_PARAMETER_BLOCK_MAGIC);

		//populate runtime parameter block fields
		rpb->isEarlyInit = slpb.isEarlyInit; //tell runtime if we started "early" or "late"

		//store runtime physical and virtual base addresses along with size
		rpb->XtVmmRuntimePhysBase = runtime_physical_base;
#ifdef __XMHF_PIE_RUNTIME__
		rpb->XtVmmRuntimeVirtBase = __TARGET_BASE + rpb->XtVmmRelocationOffset;
		HALT_ON_ERRORCOND(sl_baseaddr == rpb->XtVmmRelocationOffset + __TARGET_BASE_SL);
#else /* !__XMHF_PIE_RUNTIME__ */
		rpb->XtVmmRuntimeVirtBase = __TARGET_BASE;
#endif /* __XMHF_PIE_RUNTIME__ */
		rpb->XtVmmRuntimeSize = slpb.runtime_size;

#ifdef __XMHF_PIE_RUNTIME__
		// Make sure XtVmmRelocationOffset does not overflow.
		{
			hva_t begin = rpb->XtVmmRuntimeVirtBase;
			hva_t end = rpb->XtVmmRuntimeVirtBase + rpb->XtVmmRuntimeSize;
			HALT_ON_ERRORCOND(begin < end);
		}

        printf("SL: XMHF-runtime relocation offset: 0x%lX\n", rpb->XtVmmRelocationOffset);

        // Measure XMHF runtime. The measurement must be done before <xmhf_sl_handle_rt_rela_dyn>, which modifies 
        // XMHF runtime image. 
        {
            int ret = 0;
            // [NOTE] We must not adjust <rpb->XtVmmRuntimeDataEnd> with <rpb->XtVmmRelocationOffset> before 
            // <xmhf_sl_handle_rt_rela_dyn>, because that function halts if <rpb->XtVmmRuntimeDataEnd> is changed. 
            hva_t xmhf_rt_data_end = rpb->XtVmmRuntimeDataEnd + rpb->XtVmmRelocationOffset;
            
            ret = xmhf_sl_tpm_measure_runtime(rpb, xmhf_rt_data_end);
            if(ret)
            {
                printf("SL: Measure xmhf-runtime error! status:%d\n", ret);
            }
        }

		// Modify XMHF runtime image to make it work as PIE.
		// This step should be done as early as possible.
		xmhf_sl_handle_rt_rela_dyn();
#endif /* __XMHF_PIE_RUNTIME__ */

		//store revised E820 map and number of entries
		#ifndef __XMHF_VERIFICATION__
		memcpy(hva2sla((void *)rpb->XtVmmE820Buffer), (void *)&slpb.memmapbuffer, (sizeof(slpb.memmapbuffer)) );
		#endif
		rpb->XtVmmE820NumEntries = slpb.numE820Entries;

		//store CPU table and number of CPUs
		#ifndef __XMHF_VERIFICATION__
		memcpy(hva2sla((void *)rpb->XtVmmMPCpuinfoBuffer), (void *)&slpb.cpuinfobuffer, (sizeof(PCPU) * slpb.numCPUEntries) );
		#endif
		rpb->XtVmmMPCpuinfoNumEntries = slpb.numCPUEntries;

		//setup guest OS boot module info in LPB
		rpb->XtGuestOSBootModuleBase=(hva_t)(slpb.runtime_osbootmodule_base);
		rpb->XtGuestOSBootModuleSize=(hva_t)(slpb.runtime_osbootmodule_size);

		//pass optional app module if any
		rpb->runtime_appmodule_base = (hva_t)(slpb.runtime_appmodule_base);
		rpb->runtime_appmodule_size = (hva_t)(slpb.runtime_appmodule_size);

		//pass ACPI RSDP
		rpb->uefi_acpi_rsdp = (hva_t)(slpb.uefi_acpi_rsdp);
		rpb->uefi_info = (hva_t)(slpb.uefi_info);

		rpb->XtGuestOSBootDrive = slpb.runtime_osbootdrive;

	#if defined (__DEBUG_SERIAL__)
		//pass along UART config for serial debug output
		rpb->RtmUartConfig = slpb.uart_config;
	#endif

        rpb->platform_mem_max_phy_space = slpb.platform_mem_max_phy_space;

		//pass command line configuration forward
		COMPILE_TIME_ASSERT(sizeof(slpb.cmdline) == sizeof(rpb->cmdline));
	#ifndef __XMHF_VERIFICATION__
		strncpy(rpb->cmdline, slpb.cmdline, sizeof(slpb.cmdline));
	#endif


    #ifdef __UEFI_ALLOCATE_XMHF_RUNTIME_BSS_HIGH__
        // Check: The memory region [rpb->XtVmmRuntimeBSSHighBegin, rpb->XtVmmRuntimeBSSHighBegin + XMHF_RUNTIME_LARGE_BSS_DATA_SIZE) 
        // must not overlap with the memory  [rpb->XtVmmRuntimePhysBase, rpb->XtVmmRuntimePhysBase + rpb->XtVmmRuntimeSize)
        {
            int ret = 0;

            ret = MEM_REGION_OVERLAP(slpb.runtime_bss_high_base, XMHF_RUNTIME_LARGE_BSS_DATA_SIZE, rpb->XtVmmRuntimePhysBase, rpb->XtVmmRuntimeSize);
            if(ret != 0)
            {
                printf("Invalid runtime high BSS memory!\n");
                HALT();
            }

            // Set <rpb->XtVmmRuntimeBSSHighBegin>
            {
                void* rt_bss_high = spa2hva((spa_t)slpb.runtime_bss_high_base);
                rpb->XtVmmRuntimeBSSHighBegin = (hva_t)rt_bss_high;

                printf("SL: xmhf-runtime's high BSS data:[0x%lX, 0x%lX)\n", 
                    rpb->XtVmmRuntimeBSSHighBegin, rpb->XtVmmRuntimeBSSHighBegin + XMHF_RUNTIME_LARGE_BSS_DATA_SIZE);
            }
        }
    #endif // __UEFI_ALLOCATE_XMHF_RUNTIME_BSS_HIGH__

	}

	//initialize basic platform elements
	xmhf_baseplatform_initialize();

	//sanitize cache/MTRR/SMRAM (most important is to ensure that MTRRs
	//do not contain weird mappings)
#if defined (__DRT__)
    xmhf_sl_arch_sanitize_post_launch();
#endif	//__DRT__

	// Zero .bss section of XMHF runtime.
	// We call this function after MTRR is restored, otherwise memory is not
	// cached and zeroing .bss is very slow.
#ifdef __SKIP_RUNTIME_BSS__
	xmhf_sl_clear_rt_bss();
#endif /* __SKIP_RUNTIME_BSS__ */

#if defined (__DMAP__)
	//setup DMA protection on runtime (secure loader is already DMA protected)
	xmhf_sl_arch_early_dmaprot_init(slpb.runtime_size);
#endif

	//transfer control to runtime
	xmhf_sl_arch_xfer_control_to_runtime(rpb);

#ifndef __XMHF_VERIFICATION__
	//we should never get here
	printf("SL: Fatal, should never be here!\n");
	HALT();
#else
	return;
#endif
}
