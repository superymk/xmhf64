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

//types.h - base types
#ifndef __EMHF_TYPES_H_
#define __EMHF_TYPES_H_

#include <xmhf-config.h>

#ifndef __ASSEMBLY__

#define GB(x)           (((size_t)(x)) << 30)
#define MB(x)           (((size_t)(x)) << 20)
#define KB(x)           (((size_t)(x)) << 10)

#ifdef __XMHF_I386__
    typedef u32 hva_t;  // hypervisor virtual address
    typedef u64 spa_t;  // system physical address. [NOTE] spa_t could have a value larger than 4G; e.g., PC installs
                        // 8GB physical memory but installing 32-bit software stack.
    typedef u64	spfn_t; // pfn of system physical address
    typedef u32 gva_t;  // guest virtual address
    typedef u64 gpa_t;  // guest physical address. can be 64-bit with PAE
    typedef u32 sla_t;  // secure loader address
#elif defined(__XMHF_AMD64__)
    typedef u64 hva_t;  // hypervisor virtual address
    typedef u64 spa_t;  // system physical address
    typedef u64	spfn_t; // pfn of system physical address
    typedef u64 gva_t;  // guest virtual address
    typedef u64 gpa_t;  // guest physical address
    typedef u64 sla_t;  // secure loader address
#else
    #error "Unsupported Arch"
#endif /* __I386__ */


#define INVALID_ADDR		        0
#define INVALID_VADDR		        (INVALID_ADDR)
#define INVALID_SPADDR		        (INVALID_ADDR)
#define INVALID_GPADDR		        (INVALID_ADDR)
#define INVALID_GVADDR		        (INVALID_ADDR)

#define UINT32sToUINT64(high, low) (u64)((((u64)(high)) << 32) | (low))
#ifdef __I386__
    #define UINT32sToSPADDR(high, low) (spa_t)(UINT32sToUINT64(high, low))
    #define UINT32sToSIZE(high, low) (size_t)(low)
#elif defined(__AMD64__)
    #define UINT32sToSPADDR(high, low) (spa_t)(UINT32sToUINT64(high, low))
    #define UINT32sToSIZE(high, low) (size_t)(UINT32sToUINT64(high, low))
#else
    #error "Unsupported Arch"
#endif /* __I386__ */

#define ADDR_TO_PFN(addr)		(addr >> PAGE_SHIFT_4K)

//"golden" digest values injected using CFLAGS during build process
//NOTE: NO WAY TO SELF-CHECK slbelow64K; JUST A SANITY-CHECK
typedef struct _integrity_measurement_values {
    u8 sha_sl_low[20]; // TODO: play nice with SHA_DIGEST_LENGTH in sha1.h
    u8 sha_sl_high[20];
    u8 sha_runtime[20];
} INTEGRITY_MEASUREMENT_VALUES;

//"runtime" parameter block structure; arch_rpb (in startup component)
//is the default definition
typedef struct __packed {
    u32     magic;
#ifdef __SKIP_RUNTIME_BSS__
#ifdef __XMHF_AMD64__
    u32     _padding;
    u64     XtVmmRuntimeBssBegin;
    u64     XtVmmRuntimeBssEnd;
#elif __XMHF_I386__
    u32     XtVmmRuntimeBssBegin;
    u32     XtVmmRuntimeBssEnd;
#else /* !defined(__XMHF_I386__) && !defined(__XMHF_AMD64__) */
    #error "Unsupported Arch"
#endif /* !defined(__XMHF_I386__) && !defined(__XMHF_AMD64__) */
#endif /* __SKIP_RUNTIME_BSS__ */
#ifdef __XMHF_PIE_RUNTIME__
    hva_t   XtVmmRuntimeRelaDynBegin;
    hva_t   XtVmmRuntimeRelaDynEnd;
    /* Set by bootloader, equal to (actual address - compile address). */
    hva_t   XtVmmRelocationOffset;
#endif /* __XMHF_PIE_RUNTIME__ */
    hva_t   XtVmmEntryPoint;
#ifdef __XMHF_AMD64__
    hva_t   XtVmmPml4Base;
#elif !defined(__XMHF_I386__)
    #error "Unsupported Arch"
#endif /* !defined(__XMHF_I386__) */
    hva_t   XtVmmRuntimeDataEnd;        // End of the xmhf-runtime DATA section
    hva_t   XtVmmPdptBase;
    hva_t   XtVmmPdtsBase;
    hva_t   XtGuestOSBootModuleBase;
    hva_t   XtGuestOSBootModuleSize;
    hva_t   runtime_appmodule_base;
    hva_t   runtime_appmodule_size;
    hva_t   uefi_acpi_rsdp;
    hva_t   uefi_info;
    u8      XtGuestOSBootDrive;         /* drive used to boot (can be passed to INT 13h) */
    hva_t   XtVmmStackBase;
    hva_t   XtVmmStackSize;
    hva_t   XtVmmGdt;
    hva_t   XtVmmIdt;
    hva_t   XtVmmIdtFunctionPointers;
    u32     XtVmmIdtEntries;
    sla_t   XtVmmRuntimePhysBase;
    hva_t   XtVmmRuntimeVirtBase;
    hva_t   XtVmmRuntimeSize;
    hva_t   XtVmmE820Buffer;
    u32     XtVmmE820NumEntries;
    hva_t   XtVmmMPCpuinfoBuffer;
    u32     XtVmmMPCpuinfoNumEntries;
    hva_t   XtVmmTSSBase;
#ifdef __UEFI_ALLOCATE_XMHF_RUNTIME_BSS_HIGH__
    hva_t   XtVmmRuntimeBSSHighBegin;
#endif // __UEFI_ALLOCATE_XMHF_RUNTIME_BSS_HIGH__
    u64     platform_mem_max_phy_space; /// @brief Max physical memory space of the machine
    
    uart_config_t RtmUartConfig;        /* runtime options parsed in init and passed forward */
    char cmdline[1024];                 /* runtime options parsed in init and passed forward */
    u32 isEarlyInit;                    //1 for an "early init" else 0 (late-init)
} RPB, *PRPB;

#define STRUCT_PCPU_SIZE        (16)   // sizeof(PCPU), PCPU is defined in xmhf-baseplatform.h

//"sl" parameter block structure
typedef struct __packed _sl_parameter_block {
    u32     magic;                      // magic identifier
    u32     errorHandler;               // error handler (currently unused)
    u32     isEarlyInit;                // "early" or "late" init
    u32     numE820Entries;             // number of E820 entries
    u8      memmapbuffer[1280];         // max. 64 entries of 20 bytes each describing the system memory map
    u32     numCPUEntries;              // number of cores
    u8      cpuinfobuffer[STRUCT_PCPU_SIZE * MAX_PCPU_ENTRIES];         // Describe each physical core in the system
    u32     runtime_size;               // size of the runtime image
    u32     runtime_osbootmodule_base;  // guest OS bootmodule base
    u32     runtime_osbootmodule_size;  // guest OS bootmodule size
    u32     runtime_appmodule_base;     // XMHF hypapp optional module base
    u32     runtime_appmodule_size;     // XMHF hypapp optional module size
#ifdef __XMHF_PIE_RUNTIME__
    u64     runtime_relocation_offset;  // runtime actual address - compile address
#endif /* __XMHF_PIE_RUNTIME__ */
#ifdef __UEFI_ALLOCATE_XMHF_RUNTIME_BSS_HIGH__
    u64     runtime_bss_high_base;
#endif // __UEFI_ALLOCATE_XMHF_RUNTIME_BSS_HIGH__
    
    u64     uefi_acpi_rsdp;             // APIC RSDP when boot with UEFI, or 0
    u64     uefi_info;                  // Pointer to xmhf_efi_info_t data structure
    u64     rdtsc_before_drtm;          // Performance measurements related to DRTM
    u64     rdtsc_after_drtm;
    u8      runtime_osbootdrive;        // Boot drive number (usually 0x80)

    u64     platform_mem_max_phy_space; /// @brief Max physical memory space of the machine

    /* runtime options parsed in init and passed forward */
    uart_config_t uart_config;
    char cmdline[1024]; /* runtime options parsed in init and passed forward */
} SL_PARAMETER_BLOCK;





#endif /*ifndef __ASSEMBLY__*/

#endif /* __EMHF_TYPES_H_ */
