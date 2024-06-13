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
extern void init_core_lowlevel_setup(void);

//---globals--------------------------------------------------------------------
PCPU pcpus[MAX_PCPU_ENTRIES];

//master-id table which holds LAPIC ID to VCPU mapping for each physical core
MIDTAB midtable[MAX_MIDTAB_ENTRIES] __attribute__(( section(".data") ));

//number of physical cores in the system
u32 midtable_numentries=0;

static GRUBE820 grube820list[MAX_E820_ENTRIES];
static u32 grube820list_numentries=0;        //actual number of e820 entries returned by grub

static u64 _platform_mem_max_phy_space = 0;

//---E820 parsing and handling--------------------------------------------------
//runtimesize is assumed to be 2M aligned
u32 dealwithE820(multiboot_info_t *mbi, size_t runtimesize __attribute__((unused)), u64* out_platform_mem_max_phy_space)
{
    u64 max_phys_end = 0;

#ifdef __X86__
    // On x86, physical address space must be >= 4 GiB. Memory mapping in UEFI/BIOS reports system memory and MMIO 
    // memory regions, but not memory spaces reserved by CPUs (e.g., LAPICs, IOAPICs) in <= 4 GiB space.
    max_phys_end = ADDR_4GB; 
#endif // __X86__

    //check if GRUB has a valid E820 map
    if(!(mbi->flags & MBI_MEMMAP)){
        printf("%s: no E820 map provided. HALT!\n", __FUNCTION__);
        HALT();
    }

    //zero out grub e820 list
    memset((void *)&grube820list, 0, sizeof(GRUBE820)*MAX_E820_ENTRIES);

    //grab e820 list into grube820list
    {
        // TODO: grube820list_numentries < MAX_E820_ENTRIES not checked.
        // Possible buffer overflow?
        memory_map_t *mmap;
        for ( mmap = (memory_map_t *) mbi->mmap_addr;
              (unsigned long) mmap < mbi->mmap_addr + mbi->mmap_length;
              mmap = (memory_map_t *) ((unsigned long) mmap
                                       + mmap->size + sizeof (mmap->size))){
            grube820list[grube820list_numentries].baseaddr_low = mmap->base_addr_low;
            grube820list[grube820list_numentries].baseaddr_high = mmap->base_addr_high;
            grube820list[grube820list_numentries].length_low = mmap->length_low;
            grube820list[grube820list_numentries].length_high = mmap->length_high;
            grube820list[grube820list_numentries].type = mmap->type;
            grube820list_numentries++;
        }
    }

    //debug: print grube820list
    {
        u32 i;
        printf("\noriginal system E820 map follows:\n");
        for(i=0; i < grube820list_numentries; i++)
        {
            u64 baseaddr = UINT32_TO_64(grube820list[i].baseaddr_high, grube820list[i].baseaddr_low);
            u64 length = UINT32_TO_64(grube820list[i].length_high, grube820list[i].length_low);
            u64 phys_end = baseaddr + length;

            printf("0x%08x%08x, size=0x%08x%08x (%u)\n",
                   grube820list[i].baseaddr_high, grube820list[i].baseaddr_low,
                   grube820list[i].length_high, grube820list[i].length_low,
                   grube820list[i].type);

            // Update <maxPhysEnd> to be the end of physical memory space of the machine (discovered so far)
            if(phys_end >= max_phys_end)
            {
                max_phys_end = phys_end;
            }
        }

        // Output the physical memory space of the machine
        if(out_platform_mem_max_phy_space)
            *out_platform_mem_max_phy_space = max_phys_end;
    }

    //traverse e820 list forward to find an entry with type=0x1 (free)
    //with free amount of memory for runtime
    {
        u32 foundentry=0;
        u32 slruntimephysicalbase=__TARGET_BASE_SL;	//SL + runtime base
        u32 i;

        //for(i= (int)(grube820list_numentries-1); i >=0; i--){
		for(i= 0; i < grube820list_numentries; i++){
            u32 baseaddr, size;
            baseaddr = grube820list[i].baseaddr_low;
            size = grube820list[i].length_low;

            if(grube820list[i].type == 0x1){ //free memory?
                if(grube820list[i].baseaddr_high) //greater than 4GB? then skip
                    continue;

                if(grube820list[i].length_high){
                    printf("%s: E820 parsing error (64-bit length for < 4GB). HALT!\n");
                    HALT();
                }

			 	//check if this E820 range can accomodate SL + runtime
			 	if( slruntimephysicalbase >= baseaddr && (slruntimephysicalbase + runtimesize) < (baseaddr + size) ){
                    foundentry=1;
                    break;
                }
            }
        }

        if(!foundentry){
            printf("%s: unable to find E820 memory for SL+runtime. HALT!\n");
            HALT();
        }

		//entry number we need to split is indexed by i
		printf("proceeding to revise E820...\n");

		{
            //temporary E820 table with index
            GRUBE820 te820[MAX_E820_ENTRIES];
            u32 j=0;

            //copy all entries from original E820 table until index i
            for(j=0; j < i; j++)
                memcpy((void *)&te820[j], (void *)&grube820list[j], sizeof(GRUBE820));

            //we need a maximum of 2 extra entries for the final table, make a sanity check
            HALT_ON_ERRORCOND( (grube820list_numentries+2) < MAX_E820_ENTRIES );

            //split entry i into required number of entries depending on the memory range alignments
            if( (slruntimephysicalbase == grube820list[i].baseaddr_low) && ((slruntimephysicalbase+runtimesize) == (grube820list[i].baseaddr_low+grube820list[i].length_low)) ){
                    //exact match, no split
                    te820[j].baseaddr_high=0; te820[j].length_high=0; te820[j].baseaddr_low=grube820list[i].baseaddr_low; te820[j].length_low=grube820list[i].length_low; te820[j].type=grube820list[i].type;
                    j++;
                    i++;
            }else if ( (slruntimephysicalbase == grube820list[i].baseaddr_low) && (runtimesize < grube820list[i].length_low) ){
                    //left aligned, split into 2
                    te820[j].baseaddr_high=0; te820[j].length_high=0; te820[j].baseaddr_low=grube820list[i].baseaddr_low; te820[j].length_low=runtimesize; te820[j].type=0x2;
                    j++;
                    te820[j].baseaddr_high=0; te820[j].length_high=0; te820[j].baseaddr_low=grube820list[i].baseaddr_low+runtimesize; te820[j].length_low=grube820list[i].length_low-runtimesize; te820[j].type=1;
                    j++;
                    i++;
            }else if ( ((slruntimephysicalbase+runtimesize) == (grube820list[i].baseaddr_low+grube820list[i].length_low)) && slruntimephysicalbase > grube820list[i].baseaddr_low ){
                    //right aligned, split into 2
                    te820[j].baseaddr_high=0; te820[j].length_high=0; te820[j].baseaddr_low=grube820list[i].baseaddr_low; te820[j].length_low=slruntimephysicalbase-grube820list[i].baseaddr_low; te820[j].type=0x1;
                    j++;
                    te820[j].baseaddr_high=0; te820[j].length_high=0; te820[j].baseaddr_low= slruntimephysicalbase; te820[j].length_low=runtimesize; te820[j].type=0x1;
                    j++;
                    i++;
            }else{
                    //range in the middle, split into 3
                    te820[j].baseaddr_high=0; te820[j].length_high=0; te820[j].baseaddr_low=grube820list[i].baseaddr_low; te820[j].length_low=slruntimephysicalbase-grube820list[i].baseaddr_low; te820[j].type=0x1;
                    j++;
                    te820[j].baseaddr_high=0; te820[j].length_high=0; te820[j].baseaddr_low=slruntimephysicalbase; te820[j].length_low=runtimesize; te820[j].type=0x2;
                    j++;
                    te820[j].baseaddr_high=0; te820[j].length_high=0; te820[j].baseaddr_low=slruntimephysicalbase+runtimesize; te820[j].length_low=grube820list[i].length_low-runtimesize-(slruntimephysicalbase-grube820list[i].baseaddr_low); te820[j].type=1;
                    j++;
                    i++;
            }

            //copy entries i through end of original E820 list into temporary E820 list starting at index j
            while(i < grube820list_numentries){
                memcpy((void *)&te820[j], (void *)&grube820list[i], sizeof(GRUBE820));
                i++;
                j++;
            }

            //copy temporary E820 list into global E20 list and setup final E820 entry count
            grube820list_numentries = j;
            memcpy((void *)&grube820list, (void *)&te820, (grube820list_numentries * sizeof(GRUBE820)) );
		}

		printf("E820 revision complete.\n");

		//debug: print grube820list
		{
			u32 i;
			printf("\nrevised system E820 map follows:\n");
			for(i=0; i < grube820list_numentries; i++){
				printf("0x%08x%08x, size=0x%08x%08x (%u)\n",
					   grube820list[i].baseaddr_high, grube820list[i].baseaddr_low,
					   grube820list[i].length_high, grube820list[i].length_low,
					   grube820list[i].type);
			}
		}


        return slruntimephysicalbase;
    }

}

/// @brief Return the machine's physical memory space size. 
/// @param  
/// @return 
static u64 bios_get_mem_max_phy_space(void)
{
    return _platform_mem_max_phy_space;
}




//---init main----------------------------------------------------------------
void cstartup(multiboot_info_t *mbi)
{
    u32 cpu_vendor = 0;    //CPU_VENDOR_INTEL or CPU_VENDOR_AMD
    u32 pcpus_numentries = 0;

    module_t *mod_array;
    u32 mods_count;
    size_t sl_rt_nonzero_size;

    /* parse command line */
    memset(g_cmdline, '\0', sizeof(g_cmdline));
    strncpy(g_cmdline, (char*)mbi->cmdline, sizeof(g_cmdline)-1);
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

    mod_array = (module_t*)mbi->mods_addr;
    mods_count = mbi->mods_count;

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

    printf("Boot method: BIOS\n");

    printf("INIT(early): initializing, total modules=%u\n", mods_count);

    //check CPU type (Intel vs AMD)
    cpu_vendor = get_cpu_vendor_or_die(); // HALT()'s if unrecognized

    if(CPU_VENDOR_INTEL == cpu_vendor) {
        printf("INIT(early): detected an Intel CPU\n");

#ifdef __DRT__
        /* Intel systems require an SINIT module */
        if(!txt_parse_sinit(mod_array, mods_count))
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
    dealwithMP(NULL, pcpus, &pcpus_numentries);

    // In BIOS boot, xmhf-SL and xmhf-runtime are loaded into the fixed spaddr __TARGET_BASE_SL.

    //check number of elements in mod_array. Currently bootloader assumes that
    //mod_array[0] is SL+RT, mod_array[1] is guest OS boot module.
    HALT_ON_ERRORCOND(mods_count >= 2);

    //find highest 2MB aligned physical memory address that the hypervisor
    //binary must be moved to
    sl_rt_nonzero_size = mod_array[0].mod_end - mod_array[0].mod_start;
    sl_rt_size = sl_rt_nonzero_size;

#ifdef __SKIP_RUNTIME_BSS__
    {
        RPB *rpb = (RPB *)(uintptr_t)(mod_array[0].mod_start + PA_PAGE_SIZE_2M);
        sl_rt_size = PAGE_ALIGN_UP_2M((u32)rpb->XtVmmRuntimeBssEnd - __TARGET_BASE_SL);
    }
#endif /* __SKIP_RUNTIME_BSS__ */

    hypervisor_image_baseaddress = dealwithE820(mbi, PAGE_ALIGN_UP_2M((sl_rt_size)), &_platform_mem_max_phy_space);

    //check whether multiboot modules overlap with SL+RT. mod_array[0] can
    //overlap because we will use memmove() instead of memcpy(). Currently
    //will panic if other mod_array[i] overlaps with SL+RT.
    {
        u32 i;
        _Static_assert(sizeof(hypervisor_image_baseaddress) == 4, "!");
        u32 sl_rt_start = hypervisor_image_baseaddress;
        u32 sl_rt_end;
        HALT_ON_ERRORCOND(!plus_overflow_u32(sl_rt_start, sl_rt_size));
        sl_rt_end = sl_rt_start + sl_rt_size;
        for(i=1; i < mods_count; i++) {
			HALT_ON_ERRORCOND(mod_array[i].mod_start >= sl_rt_end ||
			                  sl_rt_start >= mod_array[i].mod_end);
        }
    }

    //relocate the hypervisor binary to the above calculated address
    HALT_ON_ERRORCOND(sl_rt_nonzero_size <= sl_rt_size);
    memmove((void*)hypervisor_image_baseaddress, (void*)mod_array[0].mod_start, sl_rt_nonzero_size);

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

    //print out stats
    printf("INIT(early): relocated hypervisor binary image to 0x%08lx\n", hypervisor_image_baseaddress);
    printf("INIT(early): 2M aligned size = 0x%08lx\n", PAGE_ALIGN_UP_2M((mod_array[0].mod_end - mod_array[0].mod_start)));
    printf("INIT(early): un-aligned size = 0x%08x\n", mod_array[0].mod_end - mod_array[0].mod_start);

    //fill in "sl" parameter block
    {
        //"sl" parameter block is at hypervisor_image_baseaddress + SL_LOW_CODE_DATA_SECTION_SIZE
        slpb = (SL_PARAMETER_BLOCK *)(hypervisor_image_baseaddress + SL_LOW_CODE_DATA_SECTION_SIZE);
        HALT_ON_ERRORCOND(slpb->magic == SL_PARAMETER_BLOCK_MAGIC);
        slpb->errorHandler = 0;
        slpb->isEarlyInit = 1;    //this is an "early" init
        slpb->numE820Entries = grube820list_numentries;
        //memcpy((void *)&slpb->e820map, (void *)&grube820list, (sizeof(GRUBE820) * grube820list_numentries));
		memcpy((void *)&slpb->memmapbuffer, (void *)&grube820list, (sizeof(GRUBE820) * grube820list_numentries));
        slpb->numCPUEntries = pcpus_numentries;
        //memcpy((void *)&slpb->pcpus, (void *)&pcpus, (sizeof(PCPU) * pcpus_numentries));
        memcpy((void *)&slpb->cpuinfobuffer, (void *)&pcpus, (sizeof(PCPU) * pcpus_numentries));

        slpb->runtime_size = (mod_array[0].mod_end - mod_array[0].mod_start) - PAGE_SIZE_2M;
        slpb->runtime_osbootmodule_base = mod_array[1].mod_start;
        slpb->runtime_osbootmodule_size = (mod_array[1].mod_end - mod_array[1].mod_start);
        slpb->runtime_osbootdrive = get_tboot_boot_drive();

		//check if we have an optional app module and if so populate relevant SLPB
		//fields
		{
			u32 i, start, bytes;
			slpb->runtime_appmodule_base= 0;
			slpb->runtime_appmodule_size= 0;

			//we search from module index 2 upto and including mods_count-1
			//and grab the first non-SINIT module in the list
			for(i=2; i < mods_count; i++) {
				start = mod_array[i].mod_start;
				bytes = mod_array[i].mod_end - start;
#ifdef __DRT__
				if (is_sinit_acmod((void*) start, bytes, false)) {
					continue;
				}
#endif /* __DRT__ */
				/* Found app module */
				slpb->runtime_appmodule_base = start;
				slpb->runtime_appmodule_size = bytes;
				printf("INIT(early): found app module, base=0x%08x, size=0x%08x\n",
						slpb->runtime_appmodule_base, slpb->runtime_appmodule_size);
				break;
			}
		}

		slpb->uefi_acpi_rsdp = 0;

        // Fill <rpb->platform_mem_max_phy_space>: platform's physical address space size.
        {
            slpb->platform_mem_max_phy_space = bios_get_mem_max_phy_space();
            printf("INIT(early): Platform's physical memory space size:0x%llX\n", slpb->platform_mem_max_phy_space);
        }

#if defined (__DEBUG_SERIAL__)
        slpb->uart_config = g_uart_config;
#endif
        strncpy(slpb->cmdline, (const char *)mbi->cmdline, sizeof(slpb->cmdline));
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