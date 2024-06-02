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
#include "../hash/hash.h"

#define TPM_PCR_BOOT_STATE   (7)

//---forward prototypes---------------------------------------------------------
u32 smp_getinfo(PCPU *pcpus, u32 *num_pcpus, void *uefi_rsdp);
MPFP * MP_GetFPStructure(void);
u32 _MPFPComputeChecksum(u32 spaddr, u32 size);
static u32 isbsp(void);

//---globals--------------------------------------------------------------------
uintptr_t hypervisor_image_baseaddress;    //2M aligned highest physical memory address
//where the hypervisor binary is relocated to

//VCPU buffers for all cores
VCPU vcpubuffers[MAX_VCPU_ENTRIES] __attribute__(( section(".data") ));

//initial stacks for all cores
u8 cpustacks[RUNTIME_STACK_SIZE * MAX_PCPU_ENTRIES] __attribute__(( section(".stack") ));

SL_PARAMETER_BLOCK *slpb = NULL;

static u32 _midtable_numentries = 0;

#ifdef __DRT__
/* TODO: refactor to eliminate a lot of these globals, or at least use
 * static where appropriate */
static u8 *g_sinit_module_ptr = NULL;
static size_t g_sinit_module_size = 0;
#endif /* __DRT__ */

/* Don't break the build if the Makefile fails to define these. */
#ifndef ___RUNTIME_INTEGRITY_HASH___
#define ___RUNTIME_INTEGRITY_HASH___ BAD_INTEGRITY_HASH
#endif /*  ___RUNTIME_INTEGRITY_HASH___ */
#ifndef ___SLABOVE64K_INTEGRITY_HASH___
#define ___SLABOVE64K_INTEGRITY_HASH___ BAD_INTEGRITY_HASH
#endif /*  ___SLABOVE64K_INTEGRITY_HASH___ */
#ifndef ___SLBELOW64K_INTEGRITY_HASH___
#define ___SLBELOW64K_INTEGRITY_HASH___ BAD_INTEGRITY_HASH
#endif /*  ___SLBELOW64K_INTEGRITY_HASH___ */

// we should get all of these from the build process, but don't forget
// that here in 'init' these values are UNTRUSTED
INTEGRITY_MEASUREMENT_VALUES g_init_gold /* __attribute__(( section("") )) */ = {
    .sha_runtime = ___RUNTIME_INTEGRITY_HASH___,
    .sha_sl_high = ___SLABOVE64K_INTEGRITY_HASH___,
    .sha_sl_low = ___SLBELOW64K_INTEGRITY_HASH___
};

//size of SL + runtime in bytes
size_t sl_rt_size;
uint64_t sl_rt_base_spaddr;


//---MP config table handling---------------------------------------------------
void dealwithMP(void *uefi_rsdp, PCPU* out_pcpus, u32* out_pcpus_numentries)
{
    if(!smp_getinfo(out_pcpus, out_pcpus_numentries, uefi_rsdp)){
        printf("Fatal error with SMP detection. Halting!\n");
        HALT();
    }
}

//---INIT IPI routine-----------------------------------------------------------
static void send_init_ipi_to_all_APs(void) {
    u32 eax, edx;
    volatile u32 *icr;
    u32 timeout = 0x01000000;

    //read LAPIC base address from MSR
    rdmsr(MSR_APIC_BASE, &eax, &edx);
    HALT_ON_ERRORCOND( edx == 0 ); //APIC is below 4G
    printf("LAPIC base and status=0x%08x\n", eax);

    icr = (u32 *) (((u32)eax & 0xFFFFF000UL) + 0x300);

    //send INIT
    printf("Sending INIT IPI to all APs...\n");
    *icr = 0x000c4500UL;
    xmhf_baseplatform_arch_x86_udelay(10000);
    //wait for command completion
    while (--timeout > 0 && ((*icr) & 0x00001000U)) {
        xmhf_cpu_relax();
    }
    if(timeout == 0) {
        printf("\nERROR: send_init_ipi_to_all_APs() TIMEOUT!\n");
    }
    printf("\nDone.\n");
}





#ifdef __DRT__

/*
 * XMHF: The following symbols are taken from tboot-1.10.5
 * Changes made include:
 *  Change return type of __getsec_capabilities() to uint32_t.
 *  TODO: assuming vtd_bios_enabled() is true
 *  TODO: verify_IA32_se_svn_status() skipped
 *  TODO: get_tboot_call_racm() skipped
 * List of major symbols:
 *  read_processor_info
 *  supports_vmx
 *  supports_smx
 *  use_mwait
 *  supports_txt
 *  txt_verify_platform
 *  txt_has_error
 *  txt_display_errors
 *  txt_do_senter
 */

#define X86_EFLAGS_ID EFLAGS_ID
#define do_cpuid(a, p) cpuid(a, &p[0], &p[1], &p[2], &p[3])
#define get_tboot_mwait() (false)
#define CPUID_X86_FEATURE_XMM3   (1<<0)
#define MSR_IA32_MISC_ENABLE_MONITOR_FSM       (1<<18)
#define __getsec_capabilities(index) \
({ \
    uint32_t cap; \
    __asm__ __volatile__ (IA32_GETSEC_OPCODE "\n" \
              : "=a"(cap) \
              : "a"(IA32_GETSEC_CAPABILITIES), "b"(index)); \
    cap; \
})

/*
 * CPUID extended feature info
 */
static unsigned int g_cpuid_ext_feat_info;

/*
 * IA32_FEATURE_CONTROL_MSR
 */
static unsigned long g_feat_ctrl_msr;


static bool read_processor_info(void)
{
    unsigned long f1, f2;
     /* eax: regs[0], ebx: regs[1], ecx: regs[2], edx: regs[3] */
    uint32_t regs[4];

    /* is CPUID supported? */
    /* (it's supported if ID flag in EFLAGS can be set and cleared) */
    asm("pushf\n\t"
        "pushf\n\t"
        "pop %0\n\t"
        "mov %0,%1\n\t"
        "xor %2,%0\n\t"
        "push %0\n\t"
        "popf\n\t"
        "pushf\n\t"
        "pop %0\n\t"
        "popf\n\t"
        : "=&r" (f1), "=&r" (f2)
        : "ir" (X86_EFLAGS_ID));
    if ( ((f1^f2) & X86_EFLAGS_ID) == 0 ) {
        g_cpuid_ext_feat_info = 0;
        printf("CPUID instruction is not supported.\n");
        return false;
    }

    do_cpuid(0, regs);
    if ( regs[1] != 0x756e6547        /* "Genu" */
         || regs[2] != 0x6c65746e     /* "ntel" */
         || regs[3] != 0x49656e69 ) { /* "ineI" */
        g_cpuid_ext_feat_info = 0;
        printf("Non-Intel CPU detected.\n");
        return false;
    }
    g_cpuid_ext_feat_info = cpuid_ecx(1);

    /* read feature control msr only if processor supports VMX or SMX instructions */
    if ( (g_cpuid_ext_feat_info & CPUID_X86_FEATURE_VMX) ||
         (g_cpuid_ext_feat_info & CPUID_X86_FEATURE_SMX) ) {
        g_feat_ctrl_msr = rdmsr64(MSR_IA32_FEATURE_CONTROL);
        printf("IA32_FEATURE_CONTROL_MSR: %08lx\n", g_feat_ctrl_msr);
    }

    return true;
}

static bool supports_vmx(void)
{
    /* check that processor supports VMX instructions */
    if ( !(g_cpuid_ext_feat_info & CPUID_X86_FEATURE_VMX) ) {
        printf("ERR: CPU does not support VMX\n");
        return false;
    }
    printf("CPU is VMX-capable\n");

    /* and that VMX is enabled in the feature control MSR */
    if ( !(g_feat_ctrl_msr & IA32_FEATURE_CONTROL_MSR_ENABLE_VMX_IN_SMX) ) {
        printf("ERR: VMXON disabled by feature control MSR (%lx)\n",
               g_feat_ctrl_msr);
        return false;
    }

    return true;
}

static bool supports_smx(void)
{
    /* check that processor supports SMX instructions */
    if ( !(g_cpuid_ext_feat_info & CPUID_X86_FEATURE_SMX) ) {
        printf("ERR: CPU does not support SMX\n");
        return false;
    }
    printf("CPU is SMX-capable\n");

    /*
     * and that SMX is enabled in the feature control MSR
     */

    /* check that the MSR is locked -- BIOS should always lock it */
    if ( !(g_feat_ctrl_msr & IA32_FEATURE_CONTROL_MSR_LOCK) ) {
        printf("ERR: IA32_FEATURE_CONTROL_MSR_LOCK is not locked\n");
        /* this should not happen, as BIOS is required to lock the MSR */
#ifdef PERMISSIVE_BOOT
        /* we enable VMX outside of SMX as well so that if there was some */
        /* error in the TXT boot, VMX will continue to work */
        g_feat_ctrl_msr |= IA32_FEATURE_CONTROL_MSR_ENABLE_VMX_IN_SMX |
                           IA32_FEATURE_CONTROL_MSR_ENABLE_VMX_OUT_SMX |
                           IA32_FEATURE_CONTROL_MSR_ENABLE_SENTER |
                           IA32_FEATURE_CONTROL_MSR_SENTER_PARAM_CTL |
                           IA32_FEATURE_CONTROL_MSR_LOCK;
        wrmsrl(MSR_IA32_FEATURE_CONTROL, g_feat_ctrl_msr);
        return true;
#else
        return false;
#endif
    }

    /* check that SENTER (w/ full params) is enabled */
    if ( !(g_feat_ctrl_msr & (IA32_FEATURE_CONTROL_MSR_ENABLE_SENTER |
                              IA32_FEATURE_CONTROL_MSR_SENTER_PARAM_CTL)) ) {
        printf("ERR: SENTER disabled by feature control MSR (%lx)\n",
               g_feat_ctrl_msr);
        return false;
    }

    return true;
}

static bool use_mwait(void)
{
    return get_tboot_mwait() && (g_cpuid_ext_feat_info & CPUID_X86_FEATURE_XMM3);
}

static tb_error_t supports_txt(void)
{
    capabilities_t cap;

    /* processor must support cpuid and must be Intel CPU */
    if ( !read_processor_info() )
        return TB_ERR_SMX_NOT_SUPPORTED;

    /* processor must support SMX */
    if ( !supports_smx() )
        return TB_ERR_SMX_NOT_SUPPORTED;

    if ( use_mwait() ) {
        /* set MONITOR/MWAIT support (SENTER will clear, so always set) */
        uint64_t misc;
        misc = rdmsr64(MSR_IA32_MISC_ENABLE);
        misc |= MSR_IA32_MISC_ENABLE_MONITOR_FSM;
        wrmsr64(MSR_IA32_MISC_ENABLE, misc);
    }
    else if ( !supports_vmx() ) {
        return TB_ERR_VMX_NOT_SUPPORTED;
    }

    /* testing for chipset support requires enabling SMX on the processor */
    write_cr4(read_cr4() | CR4_SMXE);
    printf("SMX is enabled\n");

    /*
     * verify that an TXT-capable chipset is present and
     * check that all needed SMX capabilities are supported
     */

    // XMHF: Change return type of __getsec_capabilities() to uint32_t.
    cap = (capabilities_t)__getsec_capabilities(0);
    if ( cap.chipset_present ) {
        if ( cap.senter && cap.sexit && cap.parameters && cap.smctrl &&
             cap.wakeup ) {
            printf("TXT chipset and all needed capabilities present\n");
            return TB_ERR_NONE;
        }
        else
            printf("ERR: insufficient SMX capabilities (%x)\n", cap._raw);
    }
    else
        printf("ERR: TXT-capable chipset not present\n");

    /* since we are failing, we should clear the SMX flag */
    write_cr4(read_cr4() & ~CR4_SMXE);

    return TB_ERR_TXT_NOT_SUPPORTED;
}

static tb_error_t txt_verify_platform(void)
{
    txt_heap_t *txt_heap;
    tb_error_t err;
    txt_ests_t ests;

    /* check TXT supported */
    err = supports_txt();
    if ( err != TB_ERR_NONE )
        return err;

    // XMHF: TODO: assuming vtd_bios_enabled() is true
    //if ( !vtd_bios_enabled() ) {
    //    return TB_ERR_VTD_NOT_SUPPORTED;
    //}

    /* check is TXT_RESET.STS is set, since if it is SENTER will fail */
    ests = (txt_ests_t)read_pub_config_reg(TXTCR_ESTS);
    if ( ests.txt_reset_sts ) {
        printf("TXT_RESET.STS is set and SENTER is disabled (0x%02llx)\n",
               ests._raw);
        return TB_ERR_SMX_NOT_SUPPORTED;
    }

    /* verify BIOS to OS data */
    txt_heap = get_txt_heap();
    if ( !verify_bios_data(txt_heap) )
        return TB_ERR_TXT_NOT_SUPPORTED;

    return TB_ERR_NONE;
}

bool txt_has_error(void)
{
    txt_errorcode_t err;

    err = (txt_errorcode_t)read_pub_config_reg(TXTCR_ERRORCODE);
    if (err._raw == 0 || err._raw == 0xc0000001 || err._raw == 0xc0000009) {
        return false;
    }
    else {
        return true;
    }
}

/* Read values in TXT status registers */
static void txt_display_errors(void)
{
    txt_errorcode_t err;
    txt_ests_t ests;
    txt_e2sts_t e2sts;
    txt_errorcode_sw_t sw_err;
    acmod_error_t acmod_err;

    /*
     * display TXT.ERRORODE error
     */
    err = (txt_errorcode_t)read_pub_config_reg(TXTCR_ERRORCODE);
    if (txt_has_error() == false)
        printf("TXT.ERRORCODE: 0x%llx\n", err._raw);
    else
        printf("TXT.ERRORCODE: 0x%llx\n", err._raw);

    /* AC module error (don't know how to parse other errors) */
    if ( err.valid ) {
        if ( err.external == 0 )       /* processor error */
            printf("\t processor error 0x%x\n", (uint32_t)err.type);
        else {                         /* external SW error */
            sw_err._raw = err.type;
            if ( sw_err.src == 1 )     /* unknown SW error */
                printf("unknown SW error 0x%x:0x%x\n", sw_err.err1, sw_err.err2);
            else {                     /* ACM error */
                acmod_err._raw = sw_err._raw;
                if ( acmod_err._raw == 0x0 || acmod_err._raw == 0x1 ||
                     acmod_err._raw == 0x9 )
                    printf("AC module error : acm_type=0x%x, progress=0x%02x, "
                           "error=0x%x\n", acmod_err.acm_type, acmod_err.progress,
                           acmod_err.error);
                else
                    printf("AC module error : acm_type=0x%x, progress=0x%02x, "
                           "error=0x%x\n", acmod_err.acm_type, acmod_err.progress,
                           acmod_err.error);
                /* error = 0x0a, progress = 0x0d => TPM error */
                if ( acmod_err.error == 0x0a && acmod_err.progress == 0x0d )
                    printf("TPM error code = 0x%x\n", acmod_err.tpm_err);
                /* progress = 0x10 => LCP2 error */
                else if ( acmod_err.progress == 0x10 && acmod_err.lcp_minor != 0 )
                    printf("LCP2 error:  minor error = 0x%x, index = %u\n",
                           acmod_err.lcp_minor, acmod_err.lcp_index);
            }
        }
    }

    /*
     * display TXT.ESTS error
     */
    ests = (txt_ests_t)read_pub_config_reg(TXTCR_ESTS);
    if (ests._raw == 0)
        printf("TXT.ESTS: 0x%llx\n", ests._raw);
    else
        printf("TXT.ESTS: 0x%llx\n", ests._raw);

    /*
     * display TXT.E2STS error
     */
    e2sts = (txt_e2sts_t)read_pub_config_reg(TXTCR_E2STS);
    if (e2sts._raw == 0 || e2sts._raw == 0x200000000)
        printf("TXT.E2STS: 0x%llx\n", e2sts._raw);
    else
        printf("TXT.E2STS: 0x%llx\n", e2sts._raw);
}

/* Transfer control to the SL using GETSEC[SENTER] */
/*///XXX TODO not fully functional yet. Expected flow:
txt_prepare_cpu();
txt_verify_platform();
// Legacy USB?
    // disable legacy USB #SMIs
    get_tboot_no_usb();
    disable_smis();
prepare_tpm();
txt_launch_environment(mbi);*/

static bool txt_do_senter(void *phys_mle_start, size_t mle_size) 
{
    tb_error_t err;

    if (!tpm_detect()) {
        printf("ERROR: tpm_detect() failed\n");
        return false;
    }

    // XMHF: TODO: verify_IA32_se_svn_status() skipped
    // XMHF: TODO: get_tboot_call_racm() skipped
    
    if (supports_txt() != TB_ERR_NONE) {
        printf("ERROR: supports_txt() failed\n");
        return false;
    }

    txt_display_errors();

    if((err = txt_verify_platform()) != TB_ERR_NONE) {
        printf("ERROR: txt_verify_platform returned 0x%08x\n", (u32)err);
        return false;
    }
    if(!txt_prepare_cpu()) {
        printf("ERROR: txt_prepare_cpu failed.\n");
        return false;
    }

    if (!prepare_tpm()) {
        printf("ERROR: prepare_tpm() failed.\n");
        return false;
    }

    ///XXX TODO get addresses of SL, populate a mle_hdr_t
    txt_launch_environment(g_sinit_module_ptr, g_sinit_module_size,
                           phys_mle_start, mle_size);

    return false; /* unreachable if launch is successful, thus should return failure */
}

#ifdef __UEFI__
/*
 * Get SINIT module information from UEFI information.
 */
static bool txt_parse_sinit(u64 start, u64 end)
{
	void *ptr = (void *)start;
	size_t size = end - start;

	if (start == 0 || end == 0) {
		return false;
	}

	if (!is_sinit_acmod(ptr, size, false)) {
		return false;
	}

	g_sinit_module_ptr = ptr;
	g_sinit_module_size = size;
	return true;
}
#else /* !__UEFI__ */
/**
 * Check each module to see if it is an SINIT module.  If it is, set
 * the globals g_sinit_module_ptr and g_sinit_module_size to point to
 * it.
 *
 * Returns true if an SINIT module was found, false otherwise.
 */
static bool txt_parse_sinit(module_t *mod_array, unsigned int mods_count) {
    int i;
    unsigned int bytes;

    /* I can't think of a legitimate reason why this would ever be
     * this large. */
    if(mods_count > 10) {
        return false;
    }

    for(i=(int)mods_count-1; i >= 0; i--) {
        bytes = mod_array[i].mod_end - mod_array[i].mod_start;
        printf("\nChecking whether MBI module %i is SINIT...\n", i);
        if(is_sinit_acmod((void*)mod_array[i].mod_start, bytes, false)) {
            g_sinit_module_ptr = (u8*)mod_array[i].mod_start;
            g_sinit_module_size = bytes;
            printf("YES! SINIT found @ %p, %d bytes\n",
                   g_sinit_module_ptr, g_sinit_module_size);
            return true;
        } else {
            printf("no.\n");
        }
    }

    return false;
}
#endif /* __UEFI__ */

//---svm_verify_platform-------------------------------------------------------
//do some basic checks on SVM platform to ensure DRTM should work as expected
static bool svm_verify_platform(void) __attribute__((unused));
static bool svm_verify_platform(void)
{
    uint32_t eax, edx, ebx, ecx;
    uint64_t efer;

    cpuid(0x80000001, &eax, &ebx, &ecx, &edx);

    if ((ecx & SVM_CPUID_FEATURE) == 0) {
        printf("ERR: CPU does not support AMD SVM\n");
        return false;
    }

    /* Check whether SVM feature is disabled in BIOS */
    rdmsr(VM_CR_MSR, &eax, &edx);
    if (eax & VM_CR_SVME_DISABLE) {
        printf("ERR: AMD SVM Extension is disabled in BIOS\n");
        return false;
    }

    /* Turn on SVM */
    efer = rdmsr64(MSR_EFER);
    wrmsr64(MSR_EFER, efer | (1<<EFER_SVME));
    efer = rdmsr64(MSR_EFER);
    if ((efer & (1<<EFER_SVME)) == 0) {
        printf("ERR: Could not enable AMD SVM\n");
        return false;
    }

    cpuid(0x8000000A, &eax, &ebx, &ecx, &edx);
    printf("AMD SVM version %d enabled\n", eax & 0xff);

    return true;
}

//---svm_platform_checks--------------------------------------------------------
//attempt to detect if there is a platform issue that will prevent
//successful invocation of skinit
static bool svm_prepare_cpu(void)
{
    uint64_t mcg_cap, mcg_stat;
    uint64_t apicbase;
    uint32_t cr0;
    u32 i, bound;

    /* must be running at CPL 0 => this is implicit in even getting this far */
    /* since our bootstrap code loads a GDT, etc. */

    /* must be in protected mode */
    cr0 = read_cr0();
    if (!(cr0 & CR0_PE)) {
        printf("ERR: not in protected mode\n");
        return false;
    }

    /* make sure the APIC is enabled */
    apicbase = rdmsr64(MSR_APIC_BASE);
    if (!(apicbase & MSR_IA32_APICBASE_ENABLE)) {
        printf("APIC disabled\n");
        return false;
    }

    /* verify all machine check status registers are clear */

    /* no machine check in progress (IA32_MCG_STATUS.MCIP=1) */
    mcg_stat = rdmsr64(MSR_MCG_STATUS);
    if (mcg_stat & 0x04) {
        printf("machine check in progress\n");
        return false;
    }

    /* all machine check regs are clear */
    mcg_cap = rdmsr64(MSR_MCG_CAP);
    bound = (u32)mcg_cap & 0x000000ff;
    for (i = 0; i < bound; i++) {
        mcg_stat = rdmsr64(MSR_MC0_STATUS + 4*i);
        if (mcg_stat & (1ULL << 63)) {
            printf("MCG[%d] = %llx ERROR\n", i, mcg_stat);
            return false;
        }
    }

    printf("no machine check errors\n");

    /* clear microcode on all the APs handled in mp_cstartup() */
    /* put all APs in INIT handled in do_drtm() */

    /* all is well with the processor state */
    printf("CPU is ready for SKINIT\n");

    return true;
}
#endif /* __DRT__ */

/// @brief Return true iff xmhf-bootloader can use the physical TPM device (either TPM 1.2 or TPM 2.0).
/// @param out_tpm 
/// @param out_tpm_fp 
/// @return 
static bool _is_tpm_present(struct tpm_if **out_tpm, struct tpm_if_fp **out_tpm_fp)
{
    struct tpm_if *tpm = get_tpm();
    struct tpm_if_fp *tpm_fp = NULL;

// [TODO][Github-XMHF64 Issue 13] A QEMU issue? If XMHF accesses SW TPM of QEMU with tpm20.c, then QEMU reports the 
// error "Buffer Too Small" when loading the OS bootloader
#if defined(__DEBUG_QEMU__) && defined(__UEFI__) && !defined(__FORCE_TPM_1_2__)
    {
        printf("xmhf-bootloader: No support of SW TPM2.0 in QEMU!\n");
        return false;
    }
#endif // defined(__DEBUG_QEMU__) && defined(__UEFI__)

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

static void _boot_sl_far_jump(uintptr_t slbase)
{
    uintptr_t sl_entry_point;
    u16 *sl_entry_point_offset = (u16 *)slbase;
    typedef void(*FCALL)(void);
    FCALL invokesl;

    printf("\n****** NO DRTM startup ******\n");
    printf("slbase=0x%08lx, sl_entry_point_offset=0x%08hx\n", slbase, *sl_entry_point_offset);
    sl_entry_point = slbase + (uintptr_t)(*sl_entry_point_offset);
    invokesl = (FCALL)sl_entry_point;
    printf("SL entry point to transfer control to: 0x%08lx\n", invokesl);
    invokesl();
    printf("INIT(early): error(fatal), should never come here!\n");
    HALT();
}



//---do_drtm--------------------------------------------------------------------
/// @brief this establishes a dynamic root of trust
/// @param vcpu 
/// @param slbase physical memory address of start of sl
/// @param mle_size 
static void do_drtm(VCPU __attribute__((unused))*vcpu, uintptr_t slbase, size_t mle_size __attribute__((unused)))
{
    struct tpm_if *tpm = NULL;
    struct tpm_if_fp *tpm_fp = NULL;
    bool found_tpm = false;

#ifdef __MP_VERSION__
    HALT_ON_ERRORCOND(vcpu->id == 0);
    //send INIT IPI to all APs
    send_init_ipi_to_all_APs();
    printf("INIT(early): sent INIT IPI to APs\n");
#endif

    found_tpm = _is_tpm_present(&tpm, &tpm_fp);
    if(!found_tpm)
    {
        // XMHF cannot use TPM. Warn it loud.
        printf("**********************************************************************************************\n");
        printf("[INSECURITY] XMHF CANNOT USE TPM!\n");
        printf("**********************************************************************************************\n");
        _boot_sl_far_jump(slbase);
    }

    // Measure xmhf-SL into TPM PCR7 (TPM_PCR_BOOT_STATE)
    // [NOTE] Even with DRTM enabled, xmhf-bootloader must measure xmhf-SL into PCR7 to maintain the security of red OS.
    // Otherwise, remote attackers can compromise xmhf-SL or xmhf-runtime to steal Bitlocker "volume master key" without
    // getting exposed in PCR7 (or anywhere in PCR0-15). 
    {
        union sha_digest digest = {0};
        int result = 0;
        void* slbase_ptr = spa2hva((spa_t)slbase);
        size_t sl_size = TEMPORARY_HARDCODED_MLE_SIZE;

        // Measure xmhf-runtime
        printf("xmhf-bootloader: Measure xmhf-SL start\n");
        if(tpm->major == TPM12_VER_MAJOR)
        {
            result = sha1_mem(slbase_ptr, sl_size, digest.sha1_digest);
            if(result)
            {
                printf("xmhf-bootloader: Measure xmhf-sl with SHA1 error!\n");
                HALT();
            }
        }
        else if(tpm->major == TPM20_VER_MAJOR)
        {
            result = sha2_256_mem(slbase_ptr, sl_size, digest.sha2_256_digest);
            if(result)
            {
                printf("xmhf-bootloader: Measure xmhf-sl with SHA256 error!\n");
                HALT();
            }
        }
        // No need to check invalid <tpm->major> again, because we have checked it.

        //// Extend into PCRs
        if(tpm->major == TPM12_VER_MAJOR)
        {
            hash_list_t hl;

            hl.count = 1;
            hl.entries[0].alg = TB_HALG_SHA1;
            memcpy(&hl.entries[0].hash.sha1, digest.sha1_digest, SHA1_DIGEST_LENGTH);

            result = tpm_fp->pcr_extend(tpm, 0, TPM_PCR_BOOT_STATE, &hl);
            if(!result)
            {
                printf("xmhf-bootloader (TPM1.2): Extend to PCR7 error!\n");
                HALT();
            }
        }
        else if(tpm->major == TPM20_VER_MAJOR)
        {
            hash_list_t hl;

            hl.count = 1;
            hl.entries[0].alg = TB_HALG_SHA256;
            memcpy(&hl.entries[0].hash.sha256, digest.sha2_256_digest, SHA256_DIGEST_LENGTH);

            result = tpm_fp->pcr_extend(tpm, 0, TPM_PCR_BOOT_STATE, &hl);
            if(!result)
            {
                printf("xmhf-bootloader (TPM2): Extend to PCR7 error!\n");
                HALT();
            }
        }
        // No need to check invalid <tpm->major> again, because we have checked it.

        printf("xmhf-bootloader: Extended xmhf-SL measurement\n");
    }

    // Start the xmhf-SL
#if defined (__DRT__)
    if(vcpu->cpu_vendor == CPU_VENDOR_AMD)
    {
        if(!svm_verify_platform()) {
            printf("\nINIT(early): ERROR: svm_verify_platform FAILED!\n");
            HALT();
        }
        if(!svm_prepare_cpu()) {
            printf("\nINIT(early): ERROR: svm_prepare_cpu FAILED!\n");
            HALT();
        }
        //issue SKINIT
        //our secure loader is the first 64K of the hypervisor image
        printf("INIT(early): transferring control to SL via SKINIT...\n");
		#ifndef PERF_CRIT
        if(NULL != slpb) {
            slpb->rdtsc_before_drtm = rdtsc64();
        }
		#endif
        skinit(slbase);
    } else {
        printf("\n******  INIT(early): Begin TXT Stuff  ******\n");
        txt_do_senter((void*)(slbase+3*PAGE_SIZE_4K), TEMPORARY_HARDCODED_MLE_SIZE);
        printf("INIT(early): error(fatal), should never come here!\n");
        HALT();
    }

#else  //!__DRT__
	// don't use SKINIT or SENTER
	_boot_sl_far_jump(slbase);
#endif

}


void setupvcpus(u32 cpu_vendor, MIDTAB *midtable, u32 midtable_numentries){
    u32 i;
    VCPU *vcpu;

    printf("%s: cpustacks range 0x%08lx-0x%08lx in 0x%08lx chunks\n",
           __FUNCTION__, (uintptr_t)cpustacks,
           (uintptr_t)cpustacks + (RUNTIME_STACK_SIZE * MAX_VCPU_ENTRIES),
           (size_t)RUNTIME_STACK_SIZE);
    printf("%s: vcpubuffers range 0x%08lx-0x%08lx in 0x%08lx chunks\n",
           __FUNCTION__, (uintptr_t)vcpubuffers,
           (uintptr_t)vcpubuffers + (SIZE_STRUCT_VCPU * MAX_VCPU_ENTRIES),
           (size_t)SIZE_STRUCT_VCPU);

    for(i=0; i < midtable_numentries; i++){
        hva_t esp;
        vcpu = (VCPU *)((uintptr_t)vcpubuffers + (i * SIZE_STRUCT_VCPU));
        memset((void *)vcpu, 0, sizeof(VCPU));

        vcpu->cpu_vendor = cpu_vendor;

        esp = ((uintptr_t)cpustacks + (i * RUNTIME_STACK_SIZE)) + RUNTIME_STACK_SIZE;
#ifdef __I386__
        vcpu->esp = esp;
#elif defined(__AMD64__)
        vcpu->rsp = esp;
#else
    #error "Unsupported Arch"
#endif /* __I386__ */
        vcpu->id = midtable[i].cpu_lapic_id;

        midtable[i].vcpu_vaddr_ptr = (uintptr_t)vcpu;
        printf("CPU #%u: vcpu_vaddr_ptr=0x%08lx, esp=0x%08lx\n", i,
               (uintptr_t)midtable[i].vcpu_vaddr_ptr,
               (uintptr_t)esp);
    }
}


//---wakeupAPs------------------------------------------------------------------
void wakeupAPs(void)
{
    u32 eax, edx;
    volatile u32 *icr;

    //read LAPIC base address from MSR
    rdmsr(MSR_APIC_BASE, &eax, &edx);
    HALT_ON_ERRORCOND( edx == 0 ); //APIC is below 4G
    //printf("LAPIC base and status=0x%08x\n", eax);

    icr = (u32 *) (((u32)eax & 0xFFFFF000UL) + 0x300);

    {
        extern u32 _ap_bootstrap_start[], _ap_bootstrap_end[];
        memcpy((void *)0x10000, (void *)_ap_bootstrap_start, (uintptr_t)_ap_bootstrap_end - (uintptr_t)_ap_bootstrap_start + 1);
    }

#ifdef __UEFI__
    HALT_ON_ERRORCOND(0 && "TODO");
    // See __UEFI__ in initsup.S
    // Probably better to split to i386 (non-UEFI) and amd64 (UEFI) versions.
#endif /* __UEFI__ */

    //our test code is at 1000:0000, we need to send 10 as vector
    //send INIT
    printf("Sending INIT IPI to all APs...");
    *icr = 0x000c4500UL;
    xmhf_baseplatform_arch_x86_udelay(10000);
    //wait for command completion
    while ((*icr) & 0x1000U) {
        xmhf_cpu_relax();
    }
    printf("Done.\n");

    //send SIPI (twice as per the MP protocol)
    {
        int i;
        for(i=0; i < 2; i++){
            printf("Sending SIPI-%u...", i);
            *icr = 0x000c4610UL;
            xmhf_baseplatform_arch_x86_udelay(200);
            //wait for command completion
            while ((*icr) & 0x1000U) {
                xmhf_cpu_relax();
            }
            printf("Done.\n");
        }
    }

    printf("APs should be awake!\n");
}

/* The TPM must be ready for the AMD CPU to send it commands at
 * Locality 4 when executing SKINIT. Ideally all that is necessary is
 * to xmhf_tpm_deactivate_all_localities(), but some TPM's are still not
 * sufficiently "awake" after that.  Thus, make sure it successfully
 * responds to a command at some locality, *then*
 * xmhf_tpm_deactivate_all_localities().
 */
static bool svm_prepare_tpm(void) {
    uint32_t locality = EMHF_TPM_LOCALITY_PREF; /* target.h */
    bool ret = true;

    printf("INIT:TPM: prepare_tpm starting.\n");
    //dump_locality_access_regs();
    xmhf_tpm_deactivate_all_localities();
    //dump_locality_access_regs();

    if(tpm_wait_cmd_ready(locality)) {
        printf("INIT:TPM: successfully opened in Locality %d.\n", locality);
    } else {
        printf("INIT:TPM: ERROR: Locality %d could not be opened.\n", locality);
        ret = false;
    }
    xmhf_tpm_deactivate_all_localities();
    //dump_locality_access_regs();
    printf("INIT:TPM: prepare_tpm done.\n");

    return ret;
}



//---isbsp----------------------------------------------------------------------
//returns 1 if the calling CPU is the BSP, else 0
static u32 isbsp(void){
    u32 eax, edx;
    //read LAPIC base address from MSR
    rdmsr(MSR_APIC_BASE, &eax, &edx);
    HALT_ON_ERRORCOND( edx == 0 ); //APIC is below 4G

    if(eax & 0x100)
        return 1;
    else
        return 0;
}


//---CPUs must all have their microcode cleared for SKINIT to be successful-----
static void svm_clear_microcode(VCPU *vcpu){
    u32 ucode_rev;
    u32 dummy=0;

    // Current microcode patch level available via MSR read
    rdmsr(MSR_AMD64_PATCH_LEVEL, &ucode_rev, &dummy);
    printf("CPU(0x%02x): existing microcode version 0x%08x\n", vcpu->id, ucode_rev);

    if(ucode_rev != 0) {
        wrmsr(MSR_AMD64_PATCH_CLEAR, dummy, dummy);
        printf("CPU(0x%02x): microcode CLEARED\n", vcpu->id);
    }
}

void midtable_set_numentries(u32 midtable_numentries)
{
    _midtable_numentries = midtable_numentries;
}

#ifndef __SKIP_INIT_SMP__
u32 cpus_active=0; //number of CPUs that are awake, should be equal to
//_midtable_numentries -1 if all went well with the
//MP startup protocol
u32 lock_cpus_active=1; //spinlock to access the above
#endif /* __SKIP_INIT_SMP__ */




//------------------------------------------------------------------------------
//all cores enter here
void mp_cstartup (VCPU *vcpu){
    //sanity, we should be an Intel or AMD core
    HALT_ON_ERRORCOND(vcpu->cpu_vendor == CPU_VENDOR_INTEL ||
           vcpu->cpu_vendor == CPU_VENDOR_AMD);

    if(isbsp()){
        //clear microcode if AMD CPU
        if(vcpu->cpu_vendor == CPU_VENDOR_AMD){
            printf("BSP(0x%02x): Clearing microcode...\n", vcpu->id);
            svm_clear_microcode(vcpu);
            printf("BSP(0x%02x): Microcode clear.\n", vcpu->id);

            if(!svm_prepare_tpm()) {
                printf("BSP(0x%02x): ERROR: svm_prepare_tpm FAILED.\n", vcpu->id);
                // XXX TODO HALT();
            }
        }

        printf("BSP(0x%02x): Rallying APs...\n", vcpu->id);

#ifndef __SKIP_INIT_SMP__
        //increment a CPU to account for the BSP
        spin_lock(&lock_cpus_active);
        cpus_active++;
        spin_unlock(&lock_cpus_active);

        //wait for cpus_active to become _midtable_numentries -1 to indicate
        //that all APs have been successfully started
        while (cpus_active < _midtable_numentries) {
            xmhf_cpu_relax();
        }
#endif /* __SKIP_INIT_SMP__ */

        // Measure 

        //put all APs in INIT state

        printf("BSP(0x%02x): APs ready, doing DRTM...\n", vcpu->id);
        do_drtm(vcpu, hypervisor_image_baseaddress, sl_rt_size); // this function will not return

        printf("BSP(0x%02x): FATAL, should never be here!\n", vcpu->id);
        HALT();

    }else{
        //clear microcode if AMD CPU
        if(vcpu->cpu_vendor == CPU_VENDOR_AMD){
            printf("AP(0x%02x): Clearing microcode...\n", vcpu->id);
            svm_clear_microcode(vcpu);
            printf("AP(0x%02x): Microcode clear.\n", vcpu->id);
        }

        printf("AP(0x%02x): Waiting for DRTM establishment...\n", vcpu->id);

#ifndef __SKIP_INIT_SMP__
        //update the AP startup counter
        spin_lock(&lock_cpus_active);
        cpus_active++;
        spin_unlock(&lock_cpus_active);
#endif /* __SKIP_INIT_SMP__ */

        /*
         * Note: calling printf() here may lead to deadlock. After BSP
         * see cpus_active = nproc, it calls send_init_ipi_to_all_APs() to send
         * INIT interrupt to APs. If an AP receives the INIT interrupt while
         * holding the printf lock, BSP will deadlock when printing anything
         * afterwards.
         */

        HALT();
    }


}
