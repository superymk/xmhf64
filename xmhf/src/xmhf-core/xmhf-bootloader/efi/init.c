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

//init.c - EMHF early initialization blob functionality
//author: amit vasudevan (amitvasudevan@acm.org)

// author: Miao Yu (superymk). Implement SRTM and the chain of measurement missed in DRTM.

//---includes-------------------------------------------------------------------
#include <xmhf.h>
#include <common/init.h>
// #include "../hash/hash.h"

//---forward prototypes---------------------------------------------------------
/// @brief Return the machine's physical memory space size. 
/// @param  
/// @return 
extern u64 efi_get_mem_max_phy_space(void);

extern void init_core_lowlevel_setup(void);

#ifdef __UEFI_ALLOCATE_XMHF_RUNTIME_BSS_HIGH__
extern uintptr_t xmhhf_efi_allocate_large_bss_data(void);
#endif // __UEFI_ALLOCATE_XMHF_RUNTIME_BSS_HIGH__




//---globals--------------------------------------------------------------------
PCPU pcpus[MAX_PCPU_ENTRIES];

//master-id table which holds LAPIC ID to VCPU mapping for each physical core
MIDTAB midtable[MAX_MIDTAB_ENTRIES] __attribute__(( section(".data") ));

//number of physical cores in the system
u32 midtable_numentries=0;

#ifdef __UEFI_ALLOCATE_XMHF_RUNTIME_BSS_HIGH__
uintptr_t xmhf_runtime_bss_high = 0;
#endif // __UEFI_ALLOCATE_XMHF_RUNTIME_BSS_HIGH__




//---init main----------------------------------------------------------------
void cstartup(xmhf_efi_info_t *xei)
{
    u32 pcpus_numentries = 0;
    u32 cpu_vendor = 0;    //CPU_VENDOR_INTEL or CPU_VENDOR_AMD

    /* parse command line */
    memset(g_cmdline, '\0', sizeof(g_cmdline));
    strncpy(g_cmdline, xei->cmdline, sizeof(g_cmdline)-1);

    g_cmdline[sizeof(g_cmdline)-1] = '\0'; /* in case strncpy truncated */
    tboot_parse_cmdline();

#if defined (__DEBUG_SERIAL__)
    /* parse serial port params */
    {
      uart_config_t uart_config_backup = g_uart_config;
      if(!get_tboot_serial()) {
          /* TODO: What's going on here? Redundant? */
          g_uart_config = uart_config_backup;
      }
    }

    //initialize debugging early on
	xmhf_debug_init((char *)&g_uart_config);
#endif

	//welcome banner
	printf("eXtensible Modular Hypervisor Framework (XMHF) %s\n", ___XMHF_BUILD_VERSION___);
	printf("Build revision: %s\n", ___XMHF_BUILD_REVISION___);
#ifdef __XMHF_AMD64__
	printf("Subarch: amd64\n\n");
#elif __XMHF_I386__
	printf("Subarch: i386\n\n");
#else /* !defined(__XMHF_I386__) && !defined(__XMHF_AMD64__) */
    #error "Unsupported Arch"
#endif /* !defined(__XMHF_I386__) && !defined(__XMHF_AMD64__) */

    printf("Boot method: UEFI\n");

    printf("INIT(early): initializing, total modules=%u\n",
    	   xei->sinit_end == 0 ? 1 : 2);

    //check CPU type (Intel vs AMD)
    cpu_vendor = get_cpu_vendor_or_die(); // HALT()'s if unrecognized

    if(CPU_VENDOR_INTEL == cpu_vendor) {
        printf("INIT(early): detected an Intel CPU\n");

#ifdef __DRT__
        /* Intel systems require an SINIT module */
        if(!txt_parse_sinit(xei->sinit_start, xei->sinit_end))
        {
            printf("INIT(early): FATAL ERROR: Intel CPU without SINIT module!\n");
            HALT();
        }
#endif /* __DRT__ */
    } else if(CPU_VENDOR_AMD == cpu_vendor) {
        printf("INIT(early): detected an AMD CPU\n");
    } else {
        printf("INIT(early): Dazed and confused: Unknown CPU vendor %d\n", cpu_vendor);
    }

#ifdef __XMHF_AMD64__
    //check whether 64-bit is supported by the CPU
    {
        uint32_t eax, edx, ebx, ecx;
        cpuid(0x80000000U, &eax, &ebx, &ecx, &edx);
        HALT_ON_ERRORCOND(eax >= 0x80000001U);
        cpuid(0x80000001U, &eax, &ebx, &ecx, &edx);
        HALT_ON_ERRORCOND((edx & (1U << 29)) && "64-bit not supported");
    }
#elif !defined(__XMHF_I386__)
    #error "Unsupported Arch"
#endif /* !defined(__XMHF_I386__) */

    //deal with MP and get CPU table
    dealwithMP((void *)(uintptr_t)xei->acpi_rsdp, pcpus, &pcpus_numentries);

	/*
	 * In UEFI, SL+RT is already moved to correct memory location by entry-efi.c.
	 *
	 * We also do not need to deal with E820, because UEFI AllocatePages will
	 * hide SL+RT memory from guest for us.
	 *
	 * When __SKIP_RUNTIME_BSS__, the zero part of SL+RT is not initialized
	 * here. It is initialized in secure loader.
	 *
	 * Just set global variables, e.g. hypervisor_image_baseaddress.
	 */
	hypervisor_image_baseaddress = xei->slrt_start;
	HALT_ON_ERRORCOND((u64)hypervisor_image_baseaddress == xei->slrt_start);
    sl_rt_base_spaddr = xei->slrt_start;

	/* Set sl_rt_size */
	{
		u64 size64 = xei->slrt_end - xei->slrt_start;
		sl_rt_size = size64;
		HALT_ON_ERRORCOND((u64)sl_rt_size == size64);
	}

    HALT_ON_ERRORCOND(sl_rt_size > 0x200000); /* 2M */

#ifndef __SKIP_BOOTLOADER_HASH__
    /* runtime */
    print_hex("    INIT(early): *UNTRUSTED* gold runtime: ",
              g_init_gold.sha_runtime, SHA_DIGEST_LENGTH);
    hashandprint("    INIT(early): *UNTRUSTED* comp runtime: ",
                 (u8*)hypervisor_image_baseaddress+0x200000, sl_rt_size-0x200000);
    /* SL low 64K */
    print_hex("    INIT(early): *UNTRUSTED* gold SL low: ",
              g_init_gold.sha_sl_low, SHA_DIGEST_LENGTH);
    hashandprint("    INIT(early): *UNTRUSTED* comp SL low: ",
                 (u8*)hypervisor_image_baseaddress, SL_LOW_CODE_DATA_SECTION_SIZE);
    /* SL above 64K */
    print_hex("    INIT(early): *UNTRUSTED* gold SL high: ",
              g_init_gold.sha_sl_high, SHA_DIGEST_LENGTH);
    hashandprint("    INIT(early): *UNTRUSTED* comp SL high): ",
                 (u8*)hypervisor_image_baseaddress + SL_LOW_CODE_DATA_SECTION_SIZE, 0x200000-SL_LOW_CODE_DATA_SECTION_SIZE);
#endif /* !__SKIP_BOOTLOADER_HASH__ */

    //fill in "sl" parameter block
    {
        //"sl" parameter block is at hypervisor_image_baseaddress + SL_LOW_CODE_DATA_SECTION_SIZE
        slpb = (SL_PARAMETER_BLOCK *)(hypervisor_image_baseaddress + SL_LOW_CODE_DATA_SECTION_SIZE);
        HALT_ON_ERRORCOND(slpb->magic == SL_PARAMETER_BLOCK_MAGIC);
        slpb->errorHandler = 0;
        slpb->isEarlyInit = 1;    //this is an "early" init
        slpb->numE820Entries = 0;
        slpb->numCPUEntries = pcpus_numentries;
        //memcpy((void *)&slpb->pcpus, (void *)&pcpus, (sizeof(PCPU) * pcpus_numentries));
        memcpy((void *)&slpb->cpuinfobuffer, (void *)&pcpus, (sizeof(PCPU) * pcpus_numentries));


        slpb->runtime_size = sl_rt_size - PAGE_SIZE_2M;

        /*
         * When UEFI, runtime_osboot* are ignored, because XMHF does not boot
         * guest OS directly.
         */
        slpb->runtime_osbootmodule_base = 0;
        slpb->runtime_osbootmodule_size = 0;
        slpb->runtime_osbootdrive = 0;

        /*
         * When UEFI, runtime_appmodule_* are ignored, because XMHF does not
         * support it yet.
         */
		slpb->runtime_appmodule_base = 0;
		slpb->runtime_appmodule_size = 0;

		slpb->uefi_acpi_rsdp = xei->acpi_rsdp;
		slpb->uefi_info = (uintptr_t)xei;
#ifdef __DRT__
		{
			uintptr_t start = xei->sinit_start;
			uintptr_t bytes = xei->sinit_end - start;
			HALT_ON_ERRORCOND(is_sinit_acmod((void *)start, bytes, false));
		}
#endif /* __DRT__ */

#ifdef __UEFI_ALLOCATE_XMHF_RUNTIME_BSS_HIGH__
        {
            slpb->runtime_bss_high_base = xmhf_runtime_bss_high;
        }
#endif // __UEFI_ALLOCATE_XMHF_RUNTIME_BSS_HIGH__

        // Fill <rpb->platform_mem_max_phy_space>: platform's physical address space size.
        {
            slpb->platform_mem_max_phy_space = efi_get_mem_max_phy_space();
            printf("INIT(early): Platform's physical memory space size:0x%llX\n", slpb->platform_mem_max_phy_space);
        }

#if defined (__DEBUG_SERIAL__)
        slpb->uart_config = g_uart_config;
#endif
        strncpy(slpb->cmdline, xei->cmdline, sizeof(slpb->cmdline));
    }

    //switch to MP mode
    //setup Master-ID Table (MIDTABLE)
    {
        int i;
        for(i=0; i < (int)pcpus_numentries; i++){
            midtable[midtable_numentries].cpu_lapic_id = pcpus[i].lapic_id;
            midtable[midtable_numentries].vcpu_vaddr_ptr = 0;
            midtable_numentries++;
        }
        midtable_set_numentries(midtable_numentries);
    }

    //setup vcpus
    setupvcpus(cpu_vendor, midtable, midtable_numentries);
    
	/* Need C code help to set *init_gdt_base = init_gdt_start */
	{
		extern u64 init_gdt_base[];
		extern u64 init_gdt_start[];
		*init_gdt_base = (uintptr_t)init_gdt_start;
	}

#ifndef __SKIP_INIT_SMP__
    #error "INIT SMP in UEFI is not supported"
#endif /* __SKIP_INIT_SMP__ */


#ifndef __SKIP_INIT_SMP__
    //wakeup all APs
    if(midtable_numentries > 1)
        wakeupAPs();
#endif /* !__SKIP_INIT_SMP__ */

    //fall through and enter mp_cstartup via init_core_lowlevel_setup
    init_core_lowlevel_setup();

    printf("INIT(early): error(fatal), should never come here!\n");
    HALT();
}