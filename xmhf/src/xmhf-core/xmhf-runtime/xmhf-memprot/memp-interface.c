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

// EMHF memory protection component
// implementation
// author: amit vasudevan (amitvasudevan@acm.org)

#include <xmhf.h>

// initialize memory protection structures for a given core (vcpu)
void xmhf_memprot_initialize(VCPU *vcpu)
{
    xmhf_memprot_arch_initialize(vcpu);
}

// get level-1 page map address
u64 *xmhf_memprot_get_lvl1_pagemap_address(VCPU *vcpu)
{
    return xmhf_memprot_arch_get_lvl1_pagemap_address(vcpu);
}

// get level-2 page map address
u64 *xmhf_memprot_get_lvl2_pagemap_address(VCPU *vcpu)
{
    return xmhf_memprot_arch_get_lvl2_pagemap_address(vcpu);
}

// get level-3 page map address
u64 *xmhf_memprot_get_lvl3_pagemap_address(VCPU *vcpu)
{
    return xmhf_memprot_arch_get_lvl3_pagemap_address(vcpu);
}

// get level-4 page map address
u64 *xmhf_memprot_get_lvl4_pagemap_address(VCPU *vcpu)
{
    return xmhf_memprot_arch_get_lvl4_pagemap_address(vcpu);
}

// get default root page map address
u64 *xmhf_memprot_get_default_root_pagemap_address(VCPU *vcpu)
{
    return xmhf_memprot_arch_get_default_root_pagemap_address(vcpu);
}

// flush the TLB of all nested page tables in the current core
void xmhf_memprot_flushmappings_localtlb(VCPU *vcpu, u32 flags)
{
    // printf("CPU(0x%02x): <xmhf_memprot_flushmappings_localtlb>\n", vcpu->id);
    xmhf_memprot_arch_flushmappings_localtlb(vcpu, flags);
}

// flush the TLB of all nested page tables in all cores
// Requirement: Other cores has been quiesced
void xmhf_memprot_flushmappings_alltlb(VCPU *vcpu, u32 flags)
{
    HALT_ON_ERRORCOND(g_vmx_quiesce);

    // Notice all cores to flush EPT TLB
    g_vmx_flush_all_tlb_signal = flags;

    // TODO: can move this call to xmhf_smpguest_arch_x86vmx_endquiesce(), save
    // a little bit of time.
    xmhf_memprot_flushmappings_localtlb(vcpu, flags);
}

// set protection for a given physical memory address
void xmhf_memprot_setprot(VCPU *vcpu, u64 gpa, u32 prottype)
{
#ifdef __XMHF_VERIFICATION_DRIVEASSERTS__
    assert((vcpu != NULL));
    assert(((gpa < rpb->XtVmmRuntimePhysBase) ||
            (gpa >= (rpb->XtVmmRuntimePhysBase + rpb->XtVmmRuntimeSize))));
    assert(((prottype > 0) &&
            (prottype <= MEMP_PROT_MAXVALUE)));
    assert(
        (prottype == MEMP_PROT_NOTPRESENT) ||
        ((prottype & MEMP_PROT_PRESENT) && (prottype & MEMP_PROT_READONLY) && (prottype & MEMP_PROT_EXECUTE)) ||
        ((prottype & MEMP_PROT_PRESENT) && (prottype & MEMP_PROT_READWRITE) && (prottype & MEMP_PROT_EXECUTE)) ||
        ((prottype & MEMP_PROT_PRESENT) && (prottype & MEMP_PROT_READONLY) && (prottype & MEMP_PROT_NOEXECUTE)) ||
        ((prottype & MEMP_PROT_PRESENT) && (prottype & MEMP_PROT_READWRITE) && (prottype & MEMP_PROT_NOEXECUTE)));
#endif

    xmhf_memprot_arch_setprot(vcpu, gpa, prottype);
}

// get protection for a given physical memory address
u32 xmhf_memprot_getprot(VCPU *vcpu, u64 gpa)
{
    return xmhf_memprot_arch_getprot(vcpu, gpa);
}

// Is the given system paddr belong to mHV (XMHF + hypapp)?
bool xmhf_is_mhv_memory(spa_t spa)
{
    u64 base = rpb->XtVmmRuntimePhysBase;
    size_t size = rpb->XtVmmRuntimeSize;

    if ((spa >= base) && (spa < base + size))
        return true;

    return false;
}

// On 32bit machine, we always return 0 - 4G as the machine physical address range, no matter how many memory is installed
// On 64-bit machine, the function queries the E820 map for the used memory region.
bool xmhf_get_machine_paddr_range(spa_t *machine_base_spa, spa_t *machine_limit_spa)
{
    return xmhf_arch_get_machine_paddr_range(machine_base_spa, machine_limit_spa);
}

int xmhf_memprot_emulate_guest_instruction(VCPU *vcpu, struct regs *r, emu_env_t *emu_env, unsigned char *inst, uint32_t inst_len)
{
    return x86_vmx_emulate_instruction(vcpu, r, emu_env, inst, inst_len);
}

#ifdef __I386__
#define X86_INST_MAX_LEN 9
#elif defined(__AMD64__)
#define X86_INST_MAX_LEN 15
#else
#error "Unsupported Arch"
#endif /* __I386__ */

int xmhf_memprot_emulate_guest_ring0_read_size(VCPU *vcpu, struct regs *r, size_t *out_operand_size)
{
    int status = 0;
    unsigned char inst[X86_INST_MAX_LEN] = {0};
    emu_env_t ctxt;
    gva_t rip = (gva_t)VCPU_grip(vcpu);
    uint32_t len = vcpu->vmcs.info_vmexit_instruction_length;
    guestmem_hptw_ctx_pair_t ctx_pair;

    // Copy current guest's instruction
    guestmem_init(vcpu, &ctx_pair);
    guestmem_copy_gv2h(&ctx_pair, 0, inst, rip, len);

    status = xmhf_memprot_emulate_guest_instruction(vcpu, r, &ctxt, inst, len);
    if (status)
        return -1;

    // Get operand size
    if (out_operand_size)
        *out_operand_size = ctxt.dst.operand_size;

    return 0;
}

int xmhf_memprot_emulate_guest_ring0_read(VCPU *vcpu, struct regs *r, void *force_read_value)
{
    int status = 0;
    unsigned char inst[X86_INST_MAX_LEN] = {0};
    emu_env_t ctxt;
    gva_t rip = (gva_t)VCPU_grip(vcpu);
    uint32_t len = vcpu->vmcs.info_vmexit_instruction_length;
    guestmem_hptw_ctx_pair_t ctx_pair;

    // Copy current guest's instruction
    guestmem_init(vcpu, &ctx_pair);
    guestmem_copy_gv2h(&ctx_pair, 0, inst, rip, len);

    status = xmhf_memprot_emulate_guest_instruction(vcpu, r, &ctxt, inst, len);
    if (status)
        return -1;

    // Perform the read operation for the current guest
    if (ctxt.dst.type == OPERAND_REG)
    {
#ifdef __AMD64__
        printf("CPU(0x%02x): <xmhf_memprot_emulate_guest_ring0_read> ctxt.dst.reg_hvaddr:0x%lX, &r->rax:0x%lX\n", vcpu->id, (ulong_t)ctxt.dst.reg_hvaddr, (ulong_t)&r->rax);
#elif defined(__I386__)
        printf("CPU(0x%02x): <xmhf_memprot_emulate_guest_ring0_read> ctxt.dst.reg_hvaddr:0x%lX, &r->eax:0x%lX\n", vcpu->id, (ulong_t)ctxt.dst.reg_hvaddr, (ulong_t)&r->eax);
#endif
        memcpy((void *)ctxt.dst.reg_hvaddr, force_read_value, ctxt.dst.operand_size);
    }
    else if (ctxt.dst.type == OPERAND_MEM)
    {
        guestmem_copy_h2gv(&ctx_pair, 0, ctxt.dst.mem.gvaddr, force_read_value, ctxt.dst.operand_size);
    }

    return 0;
}

int xmhf_memprot_emulate_guest_ring0_write(VCPU *vcpu, struct regs *r, void *out_value, size_t *out_operand_size)
{
    int status = 0;
    unsigned char inst[X86_INST_MAX_LEN] = {0};
    emu_env_t ctxt;
    gva_t rip = (gva_t)VCPU_grip(vcpu);
    uint32_t len = vcpu->vmcs.info_vmexit_instruction_length;
    guestmem_hptw_ctx_pair_t ctx_pair;

    // Copy current guest's instruction
    guestmem_init(vcpu, &ctx_pair);
    guestmem_copy_gv2h(&ctx_pair, 0, inst, rip, len);

    status = xmhf_memprot_emulate_guest_instruction(vcpu, r, &ctxt, inst, len);
    if (status)
        return -1;

    // Parse write value and operand size from the instruction
    if (out_value)
        memcpy(out_value, ctxt.src.val, ctxt.src.operand_size);

    if (out_operand_size)
        *out_operand_size = ctxt.src.operand_size;

    return 0;
}

/********* Debug functions *********/
void xmhf_registers_dump(VCPU *vcpu, struct regs *r)
{
    gva_t rip = (gva_t)VCPU_grip(vcpu);
    printf("rip: 0x%lX\n", rip);
    printf("rax: 0x%lX \t rbx: 0x%lX \t rcx: 0x%lX \t rdx: 0x%lX \n",
           VCPU_reg_get(vcpu, r, CPU_REG_AX), VCPU_reg_get(vcpu, r, CPU_REG_BX), VCPU_reg_get(vcpu, r, CPU_REG_CX), VCPU_reg_get(vcpu, r, CPU_REG_DX));
    printf("rsi: 0x%lX \t rdi: 0x%lX \t rsp: 0x%lX \t rbp: 0x%lX \n",
           VCPU_reg_get(vcpu, r, CPU_REG_SI), VCPU_reg_get(vcpu, r, CPU_REG_DI), VCPU_reg_get(vcpu, r, CPU_REG_SP), VCPU_reg_get(vcpu, r, CPU_REG_BP));

#ifdef __AMD64__
    printf("r8: 0x%lX \t r9: 0x%lX \t r10: 0x%lX \t r11: 0x%lX \n",
           VCPU_reg_get(vcpu, r, CPU_REG_R8), VCPU_reg_get(vcpu, r, CPU_REG_R9), VCPU_reg_get(vcpu, r, CPU_REG_R10), VCPU_reg_get(vcpu, r, CPU_REG_R11));
    printf("r12: 0x%lX \t r13: 0x%lX \t r14: 0x%lX \t r15: 0x%lX \n",
           VCPU_reg_get(vcpu, r, CPU_REG_R12), VCPU_reg_get(vcpu, r, CPU_REG_R13), VCPU_reg_get(vcpu, r, CPU_REG_R14), VCPU_reg_get(vcpu, r, CPU_REG_R15));
#endif // __AMD64__
}