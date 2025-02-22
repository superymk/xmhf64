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

/*
 * EMHF base platform component; x86 backend
 * SMP initialization low-level trampoline
 */

#include <xmhf.h>

  .extern g_midtable
  .extern g_midtable_numentries
  .extern x_gdt
  .extern xmhf_baseplatform_arch_x86_smpinitialize_commonstart
  .extern xmhf_xcphandler_idt

/*------------------------------------------------------------------------------
CODE
------------------------------------------------------------------------------*/

.section .text

  /*--AP boot-strap code-------------------------------------------------------*/
  .code16
  .global _ap_bootstrap_start
  _ap_bootstrap_start:
    jmp ap_bootstrap_bypassdata
    _ap_gdtdesc:
      .word _ap_gdt_end - _ap_gdt_start - 1
      .long _ap_gdt_start - _ap_bootstrap_start + 0x10000
    .global _ap_cr3_value
    _ap_cr3_value:
      .long 0
    .global _ap_cr4_value
    _ap_cr4_value:
      .long 0
    .align 16
    _ap_gdt_start:
      .quad 0x0000000000000000  // 0x00: NULL selector
      .quad 0x00af9a000000ffff  // 0x08: 64-bit CODE selector
      .quad 0x00cf9a000000ffff  // 0x10: 32-bit CODE selector
      .quad 0x00cf92000000ffff  // 0x18: 32-bit DATA selector
      .quad 0x0000000000000000  // 0x20: TSS low (unused)
      .quad 0x0000000000000000  // 0x28: TSS high (unused)
    _ap_gdt_end:
      .word 0
    .align 16
    .global _mle_join_start
    _mle_join_start:
    .long _ap_gdt_end - _ap_gdt_start - 1 // gdt_limit
    .long _ap_gdt_start - _ap_bootstrap_start + 0x10000// gdt_base
    .long __CS32 // CS, also DS - 8
    .long _ap_clear_pipe - _ap_bootstrap_start + 0x10000 // entry point
    _mle_join_end:
    .align 16
  ap_bootstrap_bypassdata:
      movw $0x1000, %ax
      movw %ax, %ds
      movw %ax, %es
      movw $0xFFFF, %sp
      movw $0x4000, %ax
      movw %ax, %ss

      movw $0x0002, %si

      lgdt (%si)

      movl %cr0, %eax
      orl $(CR0_PE), %eax
      movl %eax, %cr0

      jmpl $__CS32, $(_ap_clear_pipe - _ap_bootstrap_start + (AP_BOOTSTRAP_CODE_SEG << 4))
    .code32
    _ap_clear_pipe:
      movw $__DS, %ax
      movw %ax, %ds
      movw %ax, %es
      movw %ax, %ss
      movw %ax, %fs
      movw %ax, %gs

      /* Set CR3 and CR4 (copy from BSP's value) */
      movl $(_ap_cr3_value - _ap_bootstrap_start + (AP_BOOTSTRAP_CODE_SEG << 4)), %esi
      movl (%esi), %ebx
      movl %ebx, %cr3
      movl $(_ap_cr4_value - _ap_bootstrap_start + (AP_BOOTSTRAP_CODE_SEG << 4)), %esi
      movl (%esi), %ebx
      movl %ebx, %cr4

      /* Set EFER MSR LME */
      movl $(MSR_EFER), %ecx
      rdmsr
      btsl $(EFER_LME), %eax
      wrmsr

      /*
       * Setup stack in 32-bits in order to perform lret. For convenience use
       * the same address as 64-bits stack.
       * TODO: this is duplicate code; consider removing
       */

      /*get hold of local APIC id*/
      mov $(MSR_APIC_BASE), %ecx
      rdmsr
      andl $0xFFFFF000, %eax
      addl $0x20, %eax
      movl (%eax), %eax
      shr $24, %eax

#ifndef __XMHF_PIE_RUNTIME__
      movl g_midtable_numentries, %edx
#else /* __XMHF_PIE_RUNTIME__ */
.global _smptrampoline_access__g_midtable_numentries
_smptrampoline_access__g_midtable_numentries:
      movl 0x79786c31, %edx
#endif /* !__XMHF_PIE_RUNTIME__ */
      /*movl g_runtime, %edx*/

      /*get vcpu virtual address of this CPU/core*/
      /*movl $(__midtable), %ebx*/

#ifndef __XMHF_PIE_RUNTIME__
      movl $(g_midtable), %ebx
#else /* __XMHF_PIE_RUNTIME__ */
.global _smptrampoline_access__g_midtable
_smptrampoline_access__g_midtable:
      movl $0x79786c32, %ebx
#endif /* !__XMHF_PIE_RUNTIME__ */

      xorl %ecx, %ecx
getvcpuloop32:
      leal 0x0(%ebx, %ecx, 8), %esp
      movl 0x0(%esp, %ecx, 8), %ebp  // ebp contains the lapic id
      cmpl %eax, %ebp
      jz gotvcpu32
      incl %ecx
      cmpl %edx, %ecx
      jb getvcpuloop32
      /*we should never get here, if so just halt*/
      hlt
gotvcpu32:
      movl 0x8(%esp, %ecx, 8), %esi // esi contains vcpu pointer
      movl 0x0(%esi), %esp          // load stack for this CPU

      /* setup jump to 64-bit mode */
      pushl $(__CS)                 /* 2nd entry in GDT (64-bit CODE) */

#ifndef __XMHF_PIE_RUNTIME__
      leal _ap_pmode_entry_with_paging, %eax
#else /* __XMHF_PIE_RUNTIME__ */
.global _smptrampoline_access___ap_pmode_entry_with_paging
_smptrampoline_access___ap_pmode_entry_with_paging:
      leal 0x79786c33, %eax
#endif /* !__XMHF_PIE_RUNTIME__ */

      pushl %eax

      /* set CR0 */
      movl %cr0, %eax
      orl $(CR0_PG), %eax
      andl $(~(CR0_NW | CR0_CD)), %eax
      movl %eax, %cr0

      /* jump to 64-bit mode */
      lret

  .global _ap_bootstrap_end
  _ap_bootstrap_end:
    nop
    nop
    nop
    nop

  .code64

  /*---AP common low-level entry point with paging enabled----------------------*/
  .global _ap_pmode_entry_with_paging
  _ap_pmode_entry_with_paging:
    /*load our gdt and idt*/
#ifndef __XMHF_PIE_RUNTIME__
    lgdt x_gdt
    lidt xmhf_xcphandler_idt
#else /* __XMHF_PIE_RUNTIME__ */
    lgdt x_gdt(%rip)
    lidt xmhf_xcphandler_idt(%rip)
#endif /* !__XMHF_PIE_RUNTIME__ */

    /*get hold of local APIC id*/
    mov $(MSR_APIC_BASE), %ecx
    rdmsr
    andl $0xFFFFF000, %eax
    addl $0x20, %eax
    movl (%eax), %eax
    shr $24, %eax

#ifndef __XMHF_PIE_RUNTIME__
    movq g_midtable_numentries, %rdx
#else /* __XMHF_PIE_RUNTIME__ */
    movq g_midtable_numentries(%rip), %rdx
#endif /* !__XMHF_PIE_RUNTIME__ */
    /*movl g_runtime, %edx*/

    /*get vcpu virtual address of this CPU/core*/
    /*movl $(__midtable), %ebx*/
#ifndef __XMHF_PIE_RUNTIME__
    movq $(g_midtable), %rbx
#else /* __XMHF_PIE_RUNTIME__ */
    leaq g_midtable(%rip), %rbx
#endif /* !__XMHF_PIE_RUNTIME__ */
    xorq %rcx, %rcx
getvcpuloop:
    leaq 0x0(%rbx, %rcx, 8), %rsp
    movl 0x0(%rsp, %rcx, 8), %ebp   // ebp contains the lapic id
    cmpl %eax, %ebp
    jz gotvcpu
    incq %rcx
    cmpq %rdx, %rcx
    jb getvcpuloop
    /*we should never get here, if so just halt*/
    hlt
gotvcpu:
   movq 0x8(%rsp, %rcx, 8), %rsi    // esi contains vcpu pointer
   movq 0x0(%rsi), %rsp             // load stack for this CPU
   movq %rsi, %rdi                  // first argument for function call
   call xmhf_baseplatform_arch_x86_smpinitialize_commonstart
   /*we should never get here, if so just halt*/
   hlt
