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

/*
 * EMHF partition component interface (x86 VMX backend)
 * author: amit vasudevan (amitvasudevan@acm.org)
 */

#include <xmhf.h>

//---globals referenced by this module------------------------------------------
//TODO: need to remove these direct references
extern u32 x_gdt_start[], x_idt_start[]; //runtimesup.S


//critical MSRs that need to be saved/restored across guest VM switches
// When changing this array, also change the following functions:
// * xmhf_partition_arch_x86vmx_get_xmhf_msr()
// * xmhf_parteventhub_arch_x86vmx_handle_wrmsr()
// * xmhf_parteventhub_arch_x86vmx_handle_rdmsr()
#ifdef __NESTED_VIRTUALIZATION__
// * xmhf_nested_arch_x86vmx_vmcs12_to_vmcs02()
// * xmhf_nested_arch_x86vmx_vmcs02_to_vmcs12()
#endif /* __NESTED_VIRTUALIZATION__ */
static const u32 vmx_msr_area_msrs[] = {
	MSR_EFER,
	MSR_IA32_PAT,
};
//count of critical MSRs that need to be saved/restored across VM switches
static const unsigned int vmx_msr_area_msrs_count = (sizeof(vmx_msr_area_msrs)/sizeof(vmx_msr_area_msrs[0]));

/* MSR bitmap for each CPU if supported by VMX */
static u8 vmx_msr_bitmaps[MAX_VCPU_ENTRIES][PAGE_SIZE_4K] __attribute__((aligned(PAGE_SIZE_4K)));

/*
 * Check whether msr is XMHF-managed (in VMCS MSR load / store area).
 * If yes, the MSR's index is written to index and true is returned.
 * If no, this function returns false.
 */
bool xmhf_partition_arch_x86vmx_get_xmhf_msr(u32 msr, u32 *index)
{
	switch (msr) {
	case MSR_EFER:
		*index = 0;
		return true;
	case MSR_IA32_PAT:
		*index = 1;
		return true;
	default:
		return false;
	}
}

//---initVT: initializes CPU VT-------------------------------------------------
static void _vmx_initVT(VCPU *vcpu){
	//step-0: to enable VMX on a core, we require it to have a TR loaded,
	//so load it for this core
	//__vmx_loadTR();
	{
	  hva_t gdtstart = (hva_t)x_gdt_start;
	  u16 trselector = 	__TRSEL;
	  static volatile u32 lock = 1;
	  /*
	   * The following assembly code modifies the GDT shared by all CPUs. Race
	   * condition between CPUs will cause a CPU to see incorrect value in the
	   * LTR instruction. Thus, locking is required.
	   *
	   * TODO: all code other than the LTR instruction can be converted to C.
	   * TODO: can probably change GDT before SMP to elimiate race condition.
	   */
	  spin_lock(&lock);
	  #ifndef __XMHF_VERIFICATION__
#ifdef __AMD64__
	  asm volatile("movq %0, %%rdi\r\n"
		"xorq %%rax, %%rax\r\n"
		"movw %1, %%ax\r\n"
		"addq %%rax, %%rdi\r\n"		//%rdi is pointer to TSS descriptor in GDT
		"addq $0x4, %%rdi\r\n"		//%rdi points to 2nd byte of 128-bit TSS desc.
		"lock andl $0xFFFF00FF, (%%rdi)\r\n"
		"lock orl  $0x00008900, (%%rdi)\r\n"
		"ltr %%ax\r\n"				//load TR
	     :
	     : "m"(gdtstart), "m"(trselector)
	     : "rdi", "rax"
	  );
#elif defined(__I386__)
	  asm volatile("movl %0, %%edi\r\n"
		"xorl %%eax, %%eax\r\n"
		"movw %1, %%ax\r\n"
		"addl %%eax, %%edi\r\n"		//%edi is pointer to TSS descriptor in GDT
		"addl $0x4, %%edi\r\n"		//%edi points to top 32-bits of 64-bit TSS desc.
		"lock andl $0xFFFF00FF, (%%edi)\r\n"
		"lock orl  $0x00008900, (%%edi)\r\n"
		"ltr %%ax\r\n"				//load TR
	     :
	     : "m"(gdtstart), "m"(trselector)
	     : "edi", "eax"
	  );
#else /* !defined(__I386__) && !defined(__AMD64__) */
    #error "Unsupported Arch"
#endif /* !defined(__I386__) && !defined(__AMD64__) */
	  #endif
	  spin_unlock(&lock);
	}



  //step-1: check if intel CPU
  {
    #ifndef __XMHF_VERIFICATION__
    if (get_cpu_vendor_or_die() != CPU_VENDOR_INTEL) {
      printf("CPU(0x%02x) is not an Intel CPU. Halting!\n", vcpu->id);
      HALT();
    }
    #endif
  }

  //step-2: check VT support
  {
    #ifndef __XMHF_VERIFICATION__
    u32 eax, ebx, ecx, edx;
    cpuid(1, &eax, &ebx, &ecx, &edx);
    if ( ( ecx & (1<<5) ) == 0 ){
      printf("CPU(0x%02x) does not support VT. Halting!\n", vcpu->id);
      HALT();
    }
    #endif
  }

  //step-3: save contents of VMX MSRs as well as MSR EFER and EFCR
  //into vcpu
  {
    u32 i;
    #ifndef __XMHF_VERIFICATION__
    for(i=0; i < IA32_VMX_MSRCOUNT; i++){
    #else
    for(i=0; i < 1; i++){
    #endif
        /* Note: was "i <= INDEX_IA32_VMX_VMFUNC_MSR" */
        if (i >= INDEX_IA32_VMX_TRUE_PINBASED_CTLS_MSR &&
            i <= IA32_VMX_TRUE_ENTRY_CTLS_MSR &&
            !(vcpu->vmx_msrs[INDEX_IA32_VMX_BASIC_MSR] & (1ULL << 55))) {
            continue;
        }
        if (i == INDEX_IA32_VMX_VMFUNC_MSR &&
            !(vcpu->vmx_msrs[INDEX_IA32_VMX_PROCBASED_CTLS2_MSR] &
              (1ULL << VMX_SECPROCBASED_ENABLE_VM_FUNCTIONS))) {
            continue;
        }
        vcpu->vmx_msrs[i] = rdmsr64(IA32_VMX_BASIC_MSR + i);
    }

    if (vcpu->vmx_msrs[INDEX_IA32_VMX_BASIC_MSR] & (1ULL << 55)) {
        vcpu->vmx_pinbased_ctls = vcpu->vmx_msrs[INDEX_IA32_VMX_TRUE_PINBASED_CTLS_MSR];
        vcpu->vmx_procbased_ctls = vcpu->vmx_msrs[INDEX_IA32_VMX_TRUE_PROCBASED_CTLS_MSR];
        vcpu->vmx_exit_ctls = vcpu->vmx_msrs[INDEX_IA32_VMX_TRUE_EXIT_CTLS_MSR];
        vcpu->vmx_entry_ctls = vcpu->vmx_msrs[INDEX_IA32_VMX_TRUE_ENTRY_CTLS_MSR];
    } else {
        vcpu->vmx_pinbased_ctls = vcpu->vmx_msrs[INDEX_IA32_VMX_PINBASED_CTLS_MSR];
        vcpu->vmx_procbased_ctls = vcpu->vmx_msrs[INDEX_IA32_VMX_PROCBASED_CTLS_MSR];
        vcpu->vmx_exit_ctls = vcpu->vmx_msrs[INDEX_IA32_VMX_EXIT_CTLS_MSR];
        vcpu->vmx_entry_ctls = vcpu->vmx_msrs[INDEX_IA32_VMX_ENTRY_CTLS_MSR];
    }

    vcpu->vmx_caps.pinbased_ctls = (vcpu->vmx_pinbased_ctls >> 32);
    vcpu->vmx_caps.procbased_ctls = (vcpu->vmx_procbased_ctls >> 32);
    vcpu->vmx_caps.procbased_ctls2 =
        (vcpu->vmx_msrs[INDEX_IA32_VMX_PROCBASED_CTLS2_MSR] >> 32);
    vcpu->vmx_caps.exit_ctls = (vcpu->vmx_exit_ctls >> 32);
    vcpu->vmx_caps.entry_ctls = (vcpu->vmx_entry_ctls >> 32);

		//check if VMX supports unrestricted guest, if so we don't need the
		//v86 monitor and the associated state transition handling
		if (_vmx_hasctl_unrestricted_guest(&vcpu->vmx_caps))
			vcpu->vmx_guest_unrestricted = 1;
		else
			vcpu->vmx_guest_unrestricted = 0;

		#if defined(__DISABLE_UG__)
		//for now disable unrestricted bit, as we still need to intercept
		//E820 mem-map access and VMX doesnt provide software INT intercept :(
		vcpu->guest_unrestricted=0;
		#endif

		if(vcpu->vmx_guest_unrestricted)
			printf("CPU(0x%02x): UNRESTRICTED-GUEST supported.\n", vcpu->id);
  }

  //step-4: enable VMX by setting CR4
	#ifndef __XMHF_VERIFICATION__
#ifdef __AMD64__
	asm(	" mov  %%cr4, %%rax	\n"\
		" bts  $13, %%rax	\n"\
		" mov  %%rax, %%cr4	" ::: "rax" );
#elif defined(__I386__)
	asm(	" mov  %%cr4, %%eax	\n"\
		" bts  $13, %%eax	\n"\
		" mov  %%eax, %%cr4	" ::: "eax" );
#else /* !defined(__I386__) && !defined(__AMD64__) */
    #error "Unsupported Arch"
#endif /* !defined(__I386__) && !defined(__AMD64__) */
	#endif
  printf("CPU(0x%02x): enabled VMX\n", vcpu->id);

	  //step-5:enter VMX root operation using VMXON
	  {
	  	u32 retval=0;
	  	u64 vmxonregion_paddr = hva2spa((void*)vcpu->vmx_vmxonregion_vaddr);
	    //set VMCS rev id
	  	#ifndef __XMHF_VERIFICATION__
	  	*((u32 *)vcpu->vmx_vmxonregion_vaddr) = (u32)vcpu->vmx_msrs[INDEX_IA32_VMX_BASIC_MSR];
	    #endif

	    #ifndef __XMHF_VERIFICATION__
#ifdef __AMD64__
	    asm( "vmxon %1 \n"
				 "jbe vmfail \n"
				 "movq $0x1, %%rax \n"
				 "movq %%rax, %0 \n"
				 "jmp vmsuccess \n"
				 "vmfail: \n"
				 "movq $0x0, %%rax \n"
				 "movq %%rax, %0 \n"
				 "vmsuccess: \n"
	       : "=m" (retval)
	       : "m"(vmxonregion_paddr)
	       : "rax");
#elif defined(__I386__)
	   	asm( "vmxon %1 \n"
				 "jbe vmfail \n"
				 "movl $0x1, %%eax \n"
				 "movl %%eax, %0 \n"
				 "jmp vmsuccess \n"
				 "vmfail: \n"
				 "movl $0x0, %%eax \n"
				 "movl %%eax, %0 \n"
				 "vmsuccess: \n"
	       : "=m" (retval)
	       : "m"(vmxonregion_paddr)
	       : "eax");
#else /* !defined(__I386__) && !defined(__AMD64__) */
    #error "Unsupported Arch"
#endif /* !defined(__I386__) && !defined(__AMD64__) */
			#endif

	    if(!retval){
	      printf("CPU(0x%02x): Fatal, unable to enter VMX root operation\n", vcpu->id);
	      HALT();
	    }

	    printf("CPU(0x%02x): Entered VMX root operation\n", vcpu->id);
	  }

}

#ifndef __UEFI__
//---vmx int 15 hook enabling function------------------------------------------
static void	_vmx_int15_initializehook(VCPU *vcpu){
	//we should only be called from the BSP
	HALT_ON_ERRORCOND(vcpu->isbsp);

	{
		/* use BDA reserved memory at 0040:00AC */
		volatile u8 *bdamemory = (volatile u8 *)0x4AC;

		/* 32-bit CS:IP for IVT INT 15 handler */
		volatile u16 *ivt_int15 = (volatile u16 *)(0x54);

		if (ivt_int15[0] == 0x00AC && ivt_int15[1] == 0x0040) {
			/*
			 * If another XMHF loads me, the IVT for INT 15h will read as
			 * 0xac:0x40. In this case we should leave the IVT as is, otherwise
			 * there will be an infinite loop of VMCALLs when a non-e820 INT
			 * 15 happens.
			 */
			printf("CPU(0x%02x): likely loaded as nested XMHF\n", vcpu->id);
			HALT_ON_ERRORCOND(bdamemory[0] == 0x0f);
			HALT_ON_ERRORCOND(bdamemory[1] == 0x01);
			HALT_ON_ERRORCOND(bdamemory[2] == 0xc1);
			HALT_ON_ERRORCOND(bdamemory[3] == 0xcf);
		} else {
			printf("CPU(0x%02x): original INT 15h handler at 0x%04x:0x%04x\n",
				vcpu->id, ivt_int15[1], ivt_int15[0]);

			//we need 8 bytes (4 for the VMCALL followed by IRET and 4 for the
			//original IVT INT 15h handler address

			//implant VMCALL followed by IRET at 0040:04AC
			bdamemory[0]= 0x0f;	//VMCALL
			bdamemory[1]= 0x01;
			bdamemory[2]= 0xc1;
			bdamemory[3]= 0xcf;	//IRET

			//store original INT 15h handler CS:IP following VMCALL and IRET
			*((volatile u16 *)(&bdamemory[4])) = ivt_int15[0];	//original IP
			*((volatile u16 *)(&bdamemory[6])) = ivt_int15[1];	//original CS


			//point IVT INT15 handler to the VMCALL instruction
			ivt_int15[0]=0x00AC;
			ivt_int15[1]=0x0040;
		}
	}
}
#endif /* !__UEFI__ */

// Set msr to cause VMEXIT when read or write in bitmap
static void set_msrbitmap(u8 *bitmap, u32 msr) {
	u32 bit_num;
	u32 bit_offset;
	u32 byte_offset;
	if (msr < 0x2000U) {
		bit_num = msr;
	} else if (0xc0000000U <= msr && msr < 0xc0002000U) {
		bit_num = msr - 0xc0000000U;
	} else {
		return;
	}
	byte_offset = bit_num / 8;
	bit_offset = bit_num % 8;
	/* Set read bit */
	bitmap[byte_offset] |= (1U << bit_offset);
	/* Set write bit */
	bitmap[byte_offset + 2048] |= (1U << bit_offset);
}

// Set msr to not cause VMEXIT when read or write in bitmap
static void clear_msrbitmap(u8 *bitmap, u32 msr) {
	u32 bit_num;
	u32 bit_offset;
	u32 byte_offset;
	if (msr < 0x2000U) {
		bit_num = msr;
	} else if (0xc0000000U <= msr && msr < 0xc0002000U) {
		bit_num = msr - 0xc0000000U;
	} else {
		return;
	}
	byte_offset = bit_num / 8;
	bit_offset = bit_num % 8;
	/* Clear read bit */
	bitmap[byte_offset] &= ~(1U << bit_offset);
	/* Clear write bit */
	bitmap[byte_offset + 2048] &= ~(1U << bit_offset);
}

// Initialize vmx_msr_bitmaps for the current VCPU
// Based on xmhf_parteventhub_arch_x86vmx_handle_wrmsr() and
// xmhf_parteventhub_arch_x86vmx_handle_rdmsr()
static void vmx_prepare_msr_bitmap(VCPU *vcpu) {
	u8 *bitmap = vmx_msr_bitmaps[vcpu->idx];
	set_msrbitmap(bitmap, IA32_MTRR_DEF_TYPE);
	set_msrbitmap(bitmap, IA32_MTRR_FIX64K_00000);
	set_msrbitmap(bitmap, IA32_MTRR_FIX16K_80000);
	set_msrbitmap(bitmap, IA32_MTRR_FIX16K_A0000);
	set_msrbitmap(bitmap, IA32_MTRR_FIX4K_C0000);
	set_msrbitmap(bitmap, IA32_MTRR_FIX4K_C8000);
	set_msrbitmap(bitmap, IA32_MTRR_FIX4K_D0000);
	set_msrbitmap(bitmap, IA32_MTRR_FIX4K_D8000);
	set_msrbitmap(bitmap, IA32_MTRR_FIX4K_E0000);
	set_msrbitmap(bitmap, IA32_MTRR_FIX4K_E8000);
	set_msrbitmap(bitmap, IA32_MTRR_FIX4K_F0000);
	set_msrbitmap(bitmap, IA32_MTRR_FIX4K_F8000);
	set_msrbitmap(bitmap, IA32_MTRR_PHYSBASE0);
	set_msrbitmap(bitmap, IA32_MTRR_PHYSMASK0);
	set_msrbitmap(bitmap, IA32_MTRR_PHYSBASE1);
	set_msrbitmap(bitmap, IA32_MTRR_PHYSMASK1);
	set_msrbitmap(bitmap, IA32_MTRR_PHYSBASE2);
	set_msrbitmap(bitmap, IA32_MTRR_PHYSMASK2);
	set_msrbitmap(bitmap, IA32_MTRR_PHYSBASE3);
	set_msrbitmap(bitmap, IA32_MTRR_PHYSMASK3);
	set_msrbitmap(bitmap, IA32_MTRR_PHYSBASE4);
	set_msrbitmap(bitmap, IA32_MTRR_PHYSMASK4);
	set_msrbitmap(bitmap, IA32_MTRR_PHYSBASE5);
	set_msrbitmap(bitmap, IA32_MTRR_PHYSMASK5);
	set_msrbitmap(bitmap, IA32_MTRR_PHYSBASE6);
	set_msrbitmap(bitmap, IA32_MTRR_PHYSMASK6);
	set_msrbitmap(bitmap, IA32_MTRR_PHYSBASE7);
	set_msrbitmap(bitmap, IA32_MTRR_PHYSMASK7);
	set_msrbitmap(bitmap, IA32_MTRR_PHYSBASE8);
	set_msrbitmap(bitmap, IA32_MTRR_PHYSMASK8);
	set_msrbitmap(bitmap, IA32_MTRR_PHYSBASE9);
	set_msrbitmap(bitmap, IA32_MTRR_PHYSMASK9);
	set_msrbitmap(bitmap, IA32_BIOS_UPDT_TRIG);
	set_msrbitmap(bitmap, IA32_X2APIC_ICR);
#ifdef __NESTED_VIRTUALIZATION__
	set_msrbitmap(bitmap, IA32_VMX_BASIC_MSR);
	set_msrbitmap(bitmap, IA32_VMX_PINBASED_CTLS_MSR);
	set_msrbitmap(bitmap, IA32_VMX_PROCBASED_CTLS_MSR);
	set_msrbitmap(bitmap, IA32_VMX_EXIT_CTLS_MSR);
	set_msrbitmap(bitmap, IA32_VMX_ENTRY_CTLS_MSR);
	set_msrbitmap(bitmap, IA32_VMX_MISC_MSR);
	set_msrbitmap(bitmap, IA32_VMX_CR0_FIXED0_MSR);
	set_msrbitmap(bitmap, IA32_VMX_CR0_FIXED1_MSR);
	set_msrbitmap(bitmap, IA32_VMX_CR4_FIXED0_MSR);
	set_msrbitmap(bitmap, IA32_VMX_CR4_FIXED1_MSR);
	set_msrbitmap(bitmap, IA32_VMX_VMCS_ENUM_MSR);
	set_msrbitmap(bitmap, IA32_VMX_PROCBASED_CTLS2_MSR);
	set_msrbitmap(bitmap, IA32_VMX_EPT_VPID_CAP_MSR);
	set_msrbitmap(bitmap, IA32_VMX_TRUE_PINBASED_CTLS_MSR);
	set_msrbitmap(bitmap, IA32_VMX_TRUE_PROCBASED_CTLS_MSR);
	set_msrbitmap(bitmap, IA32_VMX_TRUE_EXIT_CTLS_MSR);
	set_msrbitmap(bitmap, IA32_VMX_TRUE_ENTRY_CTLS_MSR);
	set_msrbitmap(bitmap, IA32_VMX_VMFUNC_MSR);
	// Note: IA32_VMX_VMFUNC_MSR temporarily not supported
	//set_msrbitmap(bitmap, IA32_VMX_VMFUNC_MSR);
#endif /* __NESTED_VIRTUALIZATION__ */
}

// Add IA32_X2APIC_ICR to vmx_msr_bitmaps for the current VCPU. This function
// is intended to be called when XMHF needs to intercept SIPI again.
void xmhf_partition_arch_x86vmx_set_msrbitmap_x2apic_icr(VCPU *vcpu) {
	u8 *bitmap = vmx_msr_bitmaps[vcpu->idx];
	set_msrbitmap(bitmap, IA32_X2APIC_ICR);
}

// Remove IA32_X2APIC_ICR from vmx_msr_bitmaps for the current VCPU. This
// function is intended to be called after SMP guest bootup completes.
void xmhf_partition_arch_x86vmx_clear_msrbitmap_x2apic_icr(VCPU *vcpu) {
	u8 *bitmap = vmx_msr_bitmaps[vcpu->idx];
	clear_msrbitmap(bitmap, IA32_X2APIC_ICR);
}

/* Set the state of guest to after INIT interrupt, as specified by Intel SDM */
void xmhf_partition_arch_x86vmx_guestVMCS_INIT(VCPU *vcpu)
{
	/* Guest is active */
	vcpu->vmcs.guest_activity_state = 0;
	//Let guest think CR0 is set to 0x60000010U, but actually set fixed bits
	// 0x60000010U means real-mode, PE and PG bits cleared, set ET bit
	// Modify mask to trap access to CR0 fixed bits.
	// Make sure to change vmx_handle_intercept_cr0access_ug() if changing
	// control_CR0_mask.
	vcpu->vmcs.guest_CR0 = vcpu->vmx_msrs[INDEX_IA32_VMX_CR0_FIXED0_MSR];
	vcpu->vmcs.guest_CR0 &= ~(CR0_PE);
	vcpu->vmcs.guest_CR0 &= ~(CR0_PG);
	vcpu->vmcs.guest_CR0 |= CR0_ET;
	vcpu->vmcs.control_CR0_mask = vcpu->vmx_msrs[INDEX_IA32_VMX_CR0_FIXED0_MSR];
	vcpu->vmcs.control_CR0_mask &= ~(CR0_PE);
	vcpu->vmcs.control_CR0_mask &= ~(CR0_PG);
	vcpu->vmcs.control_CR0_mask |= CR0_CD;
	vcpu->vmcs.control_CR0_mask |= CR0_NW;
	vcpu->vmcs.control_CR0_shadow = CR0_CD | CR0_NW | CR0_ET;
	//Let guest think CR4 is set to 0, but actually set fixed bits
	// Modify mask to trap access to CR4 fixed bits.
	// Make sure to change vmx_handle_intercept_cr4access_ug() if changing
	// control_CR4_mask.
	vcpu->vmcs.guest_CR4 = vcpu->vmx_msrs[INDEX_IA32_VMX_CR4_FIXED0_MSR];
	vcpu->vmcs.control_CR4_mask = vcpu->vmx_msrs[INDEX_IA32_VMX_CR4_FIXED0_MSR];
	vcpu->vmcs.control_CR4_shadow = 0;
	//CR3 set to 0, does not matter
	vcpu->vmcs.guest_CR3 = 0;
	//IDTR
	vcpu->vmcs.guest_IDTR_base = 0;
	vcpu->vmcs.guest_IDTR_limit = 0xffff;
	//GDTR
	vcpu->vmcs.guest_GDTR_base = 0;
	vcpu->vmcs.guest_GDTR_limit = 0xffff;
	//LDTR, unusable
	vcpu->vmcs.guest_LDTR_base = 0;
	vcpu->vmcs.guest_LDTR_limit = 0xffff;
	vcpu->vmcs.guest_LDTR_selector = 0;
	vcpu->vmcs.guest_LDTR_access_rights = 0x10000;
	// TR, should be usable for VMX to work, but not used by guest
	// In 32-bit guest, TR access rights can be 0x83 (16-bit busy TSS) or 0x8b
	// (32-bit busy TSS). In 64-bit guest, it has to be 0x8b. So use 0x8b
	// (64-bit busy TSS). So use 0x8b here.
	vcpu->vmcs.guest_TR_base = 0;
	vcpu->vmcs.guest_TR_limit = 0;
	vcpu->vmcs.guest_TR_selector = 0;
	vcpu->vmcs.guest_TR_access_rights = 0x8b; //present, 32/64-bit busy TSS
	//DR7
	vcpu->vmcs.guest_DR7 = 0x400;
	//RSP
	vcpu->vmcs.guest_RSP = 0x0;
	//RIP
	vcpu->vmcs.guest_CS_selector = (vcpu->sipivector * PAGE_SIZE_4K) >> 4;
	vcpu->vmcs.guest_CS_base = (vcpu->sipivector * PAGE_SIZE_4K);
	vcpu->vmcs.guest_RIP = 0x0ULL;
	//RFLAGS
	vcpu->vmcs.guest_RFLAGS = (1<<1);					// reserved 1-bits
	//CS, DS, ES, FS, GS and SS segments
	vcpu->vmcs.guest_CS_limit = 0xFFFF;	//64K
	vcpu->vmcs.guest_CS_access_rights = 0x93; //present, system, read-write accessed
	vcpu->vmcs.guest_DS_selector = 0;
	vcpu->vmcs.guest_DS_base = 0;
	vcpu->vmcs.guest_DS_limit = 0xFFFF;	//64K
	vcpu->vmcs.guest_DS_access_rights = 0x93; //present, system, read-write accessed
	vcpu->vmcs.guest_ES_selector = 0;
	vcpu->vmcs.guest_ES_base = 0;
	vcpu->vmcs.guest_ES_limit = 0xFFFF;	//64K
	vcpu->vmcs.guest_ES_access_rights = 0x93; //present, system, read-write accessed
	vcpu->vmcs.guest_FS_selector = 0;
	vcpu->vmcs.guest_FS_base = 0;
	vcpu->vmcs.guest_FS_limit = 0xFFFF;	//64K
	vcpu->vmcs.guest_FS_access_rights = 0x93; //present, system, read-write accessed
	vcpu->vmcs.guest_GS_selector = 0;
	vcpu->vmcs.guest_GS_base = 0;
	vcpu->vmcs.guest_GS_limit = 0xFFFF;	//64K
	vcpu->vmcs.guest_GS_access_rights = 0x93; //present, system, read-write accessed
	vcpu->vmcs.guest_SS_selector = 0x0;
	vcpu->vmcs.guest_SS_base = 0x0;
	vcpu->vmcs.guest_SS_limit = 0xFFFF;	//64K
	vcpu->vmcs.guest_SS_access_rights = 0x93; //present, system, read-write accessed
}

#ifdef __UEFI__

/*
 * Set the state of guest for BSP when booted by UEFI, as recorded in
 * bootloader's efi.c.
 */
static void xmhf_partition_arch_x86vmx_guestVMCS_UEFI(VCPU *vcpu,
													  vmx_ctls_t *vmx_ctls)
{
	/*
	 * For UEFI, BSP needs to resume the EFI service. Thus, load guest state
	 * from bootloader data (untrusted).
	 */
	xmhf_efi_info_t *xei = (xmhf_efi_info_t *)(uintptr_t)rpb->uefi_info;

#define LOAD_XEI(x) do { vcpu->vmcs.x = xei->x; } while (0)
	LOAD_XEI(guest_ES_selector);
	LOAD_XEI(guest_CS_selector);
	LOAD_XEI(guest_SS_selector);
	LOAD_XEI(guest_DS_selector);
	LOAD_XEI(guest_FS_selector);
	LOAD_XEI(guest_GS_selector);
	LOAD_XEI(guest_LDTR_selector);
	LOAD_XEI(guest_TR_selector);
	LOAD_XEI(guest_PDPTE0);
	LOAD_XEI(guest_PDPTE1);
	LOAD_XEI(guest_PDPTE2);
	LOAD_XEI(guest_PDPTE3);
	LOAD_XEI(guest_ES_limit);
	LOAD_XEI(guest_CS_limit);
	LOAD_XEI(guest_SS_limit);
	LOAD_XEI(guest_DS_limit);
	LOAD_XEI(guest_FS_limit);
	LOAD_XEI(guest_GS_limit);
	LOAD_XEI(guest_LDTR_limit);
	LOAD_XEI(guest_TR_limit);
	LOAD_XEI(guest_GDTR_limit);
	LOAD_XEI(guest_IDTR_limit);
	LOAD_XEI(guest_ES_access_rights);
	LOAD_XEI(guest_CS_access_rights);
	LOAD_XEI(guest_SS_access_rights);
	LOAD_XEI(guest_DS_access_rights);
	LOAD_XEI(guest_FS_access_rights);
	LOAD_XEI(guest_GS_access_rights);
	LOAD_XEI(guest_LDTR_access_rights);
	LOAD_XEI(guest_TR_access_rights);
	LOAD_XEI(guest_SYSENTER_CS);
	LOAD_XEI(guest_CR3);
	LOAD_XEI(guest_ES_base);
	LOAD_XEI(guest_CS_base);
	LOAD_XEI(guest_SS_base);
	LOAD_XEI(guest_DS_base);
	LOAD_XEI(guest_FS_base);
	LOAD_XEI(guest_GS_base);
	LOAD_XEI(guest_LDTR_base);
	LOAD_XEI(guest_TR_base);
	LOAD_XEI(guest_GDTR_base);
	LOAD_XEI(guest_IDTR_base);
	LOAD_XEI(guest_DR7);
	LOAD_XEI(guest_RSP);
	LOAD_XEI(guest_RIP);
	LOAD_XEI(guest_RFLAGS);
	LOAD_XEI(guest_SYSENTER_ESP);
	LOAD_XEI(guest_SYSENTER_EIP);
#undef LOAD_XEI

	/* Guest is active */
	{
		vcpu->vmcs.guest_activity_state = 0;
	}

	/* CR0 need to be restored to guest_CR0 and control_CR0_shadow. */
	{
		ulong_t fixed0 = vcpu->vmx_msrs[INDEX_IA32_VMX_CR0_FIXED0_MSR];
		ulong_t fixed1 = vcpu->vmx_msrs[INDEX_IA32_VMX_CR0_FIXED1_MSR];
		fixed0 &= ~(CR0_PG | CR0_PE);
		vcpu->vmcs.control_CR0_mask = fixed0;
		vcpu->vmcs.control_CR0_mask &= ~(CR0_PE);
		vcpu->vmcs.control_CR0_mask &= ~(CR0_PG);
		vcpu->vmcs.control_CR0_mask |= CR0_CD;
		vcpu->vmcs.control_CR0_mask |= CR0_NW;
		vcpu->vmcs.control_CR0_shadow = xei->guest_CR0;
		vcpu->vmcs.guest_CR0 = xei->guest_CR0;
		vcpu->vmcs.guest_CR0 |= fixed0;
		vcpu->vmcs.guest_CR0 &= fixed1;
	}

	/* CR4 need to be restored to guest_CR4 and control_CR4_shadow. */
	{
		ulong_t fixed0 = vcpu->vmx_msrs[INDEX_IA32_VMX_CR4_FIXED0_MSR];
		ulong_t fixed1 = vcpu->vmx_msrs[INDEX_IA32_VMX_CR4_FIXED1_MSR];
		vcpu->vmcs.control_CR4_mask = fixed0;
		vcpu->vmcs.control_CR4_shadow = xei->guest_CR4;
		vcpu->vmcs.guest_CR4 = xei->guest_CR4;
		vcpu->vmcs.guest_CR4 |= fixed0;
		vcpu->vmcs.guest_CR4 &= fixed1;
	}

	/* Handle MSR load area */
	{
		msr_entry_t *gmsr = (msr_entry_t *)vcpu->vmx_vaddr_msr_area_guest;
		HALT_ON_ERRORCOND(vmx_msr_area_msrs_count == 2);
		HALT_ON_ERRORCOND(gmsr[0].index == MSR_EFER);
		gmsr[0].data = xei->guest_IA32_EFER;
		HALT_ON_ERRORCOND(gmsr[1].index == MSR_IA32_PAT);
		gmsr[1].data = xei->guest_IA32_PAT;
	}

	/* Handle IA-32e guest */
	if (xei->guest_IA32_EFER & (1U << EFER_LME)) {
		_vmx_setctl_vmentry_ia_32e_mode_guest(vmx_ctls);
	}
}

#else /* !__UEFI__ */

/* Set the state of guest for BSP when booted by BIOS, as specified by BIOS */
static void xmhf_partition_arch_x86vmx_guestVMCS_BIOS(VCPU *vcpu)
{
	/* Reuse code for setting VMCS to state of INIT */
	xmhf_partition_arch_x86vmx_guestVMCS_INIT(vcpu);

	// Set CR0 = 0x00000010U (e.g. after QEMU's SeaBIOS jumps to 0x7c00)
	vcpu->vmcs.control_CR0_shadow = CR0_ET;
	vcpu->vmcs.guest_IDTR_limit = 0x3ff;	//16-bit IVT
	vcpu->vmcs.guest_GDTR_limit = 0;		//no GDT
	vcpu->vmcs.guest_LDTR_limit = 0;
	vcpu->vmcs.guest_CS_selector = 0;
	vcpu->vmcs.guest_CS_base = 0;
	vcpu->vmcs.guest_RIP = 0x7c00ULL;
	vcpu->vmcs.guest_RFLAGS &= ~((1<<3)|(1<<5)|(1<<15));	// reserved 0-bits
	vcpu->vmcs.guest_RFLAGS |= (1<<9);				// IF = enable
	vcpu->vmcs.guest_RFLAGS &= ~(1<<14);			// Nested Task = disable

	//Copy first sector of disk to boot
	printf("BSP(0x%02x): copying boot-module to boot guest\n", vcpu->id);
	#ifndef __XMHF_VERIFICATION__
	memcpy((void *)__GUESTOSBOOTMODULE_BASE, (void *)rpb->XtGuestOSBootModuleBase, rpb->XtGuestOSBootModuleSize);
	#endif
}

#endif /* __UEFI__ */

//--initunrestrictedguestVMCS: initializes VMCS for unrestricted guest ---------
void vmx_initunrestrictedguestVMCS(VCPU *vcpu){
	//setup default VMX controls
	vmx_ctls_t vmx_ctls = {
		.pinbased_ctls = (u32)vcpu->vmx_pinbased_ctls,
		.procbased_ctls = (u32)vcpu->vmx_procbased_ctls,
		.procbased_ctls2 = (u32)vcpu->vmx_msrs[INDEX_IA32_VMX_PROCBASED_CTLS2_MSR],
		.exit_ctls = (u32)vcpu->vmx_exit_ctls,
		.entry_ctls = (u32)vcpu->vmx_entry_ctls,
	};

	//setup host state
	vcpu->vmcs.host_CR0 = read_cr0();
	vcpu->vmcs.host_CR4 = read_cr4();
	vcpu->vmcs.host_CR3 = read_cr3();
	vcpu->vmcs.host_CS_selector = read_segreg_cs();
	vcpu->vmcs.host_DS_selector = read_segreg_ds();
	vcpu->vmcs.host_ES_selector = read_segreg_es();
	vcpu->vmcs.host_FS_selector = read_segreg_fs();
	vcpu->vmcs.host_GS_selector = read_segreg_gs();
	vcpu->vmcs.host_SS_selector = read_segreg_ss();
	vcpu->vmcs.host_TR_selector = read_tr_sel();
	vcpu->vmcs.host_GDTR_base = (u64)(hva_t)x_gdt_start;
	vcpu->vmcs.host_IDTR_base = (u64)(hva_t)xmhf_xcphandler_get_idt_start();
	vcpu->vmcs.host_TR_base = (u64)(hva_t)g_runtime_TSS;
	vcpu->vmcs.host_RIP = (u64)(hva_t)xmhf_parteventhub_arch_x86vmx_entry;

#ifdef __XMHF_VERIFICATION_DRIVEASSERTS__
	if( vcpu->vmcs.host_RIP == (u64)(hva_t)xmhf_parteventhub_arch_x86vmx_entry)
		vcpu->vmcs.host_RIP = 0xDEADBEEF;
#endif //__XMHF_VERIFICATION__

	//store vcpu at TOS
#ifdef __AMD64__
	vcpu->rsp = vcpu->rsp - sizeof(hva_t);
#elif defined(__I386__)
	vcpu->esp = vcpu->esp - sizeof(hva_t);
#else /* !defined(__I386__) && !defined(__AMD64__) */
    #error "Unsupported Arch"
#endif /* !defined(__I386__) && !defined(__AMD64__) */
#ifndef __XMHF_VERIFICATION__
#ifdef __AMD64__
	*(hva_t *)vcpu->rsp = (hva_t)vcpu;
#elif defined(__I386__)
	*(hva_t *)vcpu->esp = (hva_t)vcpu;
#else /* !defined(__I386__) && !defined(__AMD64__) */
    #error "Unsupported Arch"
#endif /* !defined(__I386__) && !defined(__AMD64__) */
#endif
#ifdef __AMD64__
	vcpu->vmcs.host_RSP = (u64)vcpu->rsp;
#elif defined(__I386__)
	vcpu->vmcs.host_RSP = (u64)vcpu->esp;
#else /* !defined(__I386__) && !defined(__AMD64__) */
    #error "Unsupported Arch"
#endif /* !defined(__I386__) && !defined(__AMD64__) */


#ifndef __XMHF_VERIFICATION__
	vcpu->vmcs.host_SYSENTER_CS = rdmsr64(IA32_SYSENTER_CS_MSR);
	vcpu->vmcs.host_SYSENTER_ESP = rdmsr64(IA32_SYSENTER_ESP_MSR);
	vcpu->vmcs.host_SYSENTER_EIP = rdmsr64(IA32_SYSENTER_EIP_MSR);
	vcpu->vmcs.host_FS_base = rdmsr64(IA32_MSR_FS_BASE);
	vcpu->vmcs.host_GS_base = rdmsr64(IA32_MSR_GS_BASE);
#endif

#ifdef __AMD64__
	/*
	 * For amd64, set the Host address-space size (bit 9) in
	 * control_VM_exit_controls. First check whether setting this bit is
	 * allowed.
	 */
	HALT_ON_ERRORCOND(_vmx_hasctl_vmexit_host_address_space_size(&vcpu->vmx_caps));
	_vmx_setctl_vmexit_host_address_space_size(&vmx_ctls);
#elif !defined(__I386__)
    #error "Unsupported Arch"
#endif /* !defined(__I386__) */

	//IO bitmap support
	{
	    u64 addr = hva2spa((void*)vcpu->vmx_vaddr_iobitmap);
	    vcpu->vmcs.control_IO_BitmapA_address = addr;
    }
    {
        u64 addr = hva2spa( ((void*)vcpu->vmx_vaddr_iobitmap + PAGE_SIZE_4K) );
	    vcpu->vmcs.control_IO_BitmapB_address = addr;
    }
    _vmx_setctl_use_io_bitmaps(&vmx_ctls);

	//Critical MSR load/store
	{
		u32 i;
		msr_entry_t *hmsr = (msr_entry_t *)vcpu->vmx_vaddr_msr_area_host;
		msr_entry_t *gmsr = (msr_entry_t *)vcpu->vmx_vaddr_msr_area_guest;

		#ifndef __XMHF_VERIFICATION__
		//store initial values of the MSRs
		for(i=0; i < vmx_msr_area_msrs_count; i++){
			u32 msr = vmx_msr_area_msrs[i];
			hmsr[i].index = gmsr[i].index = msr;
			hmsr[i].data = gmsr[i].data = rdmsr64(msr);
#ifdef __AMD64__
			if (msr == MSR_EFER) {
			    /*
			     * Host is in amd64, but guest should enter from x86.
			     * Need to manually clear MSR_EFER's 8th bit (LME) and
			     * 10th bit (LMA). Otherwise when guest enables paging
			     * a #GP exception will occur.
			     */
			    gmsr[i].data &= ~((1LU << EFER_LME) | (1LU << EFER_LMA));
			}
#elif !defined(__I386__)
    #error "Unsupported Arch"
#endif /* !defined(__I386__) */
		}
		#endif

		//host MSR load on exit, we store it ourselves before entry
		{
		    u64 addr = hva2spa((void*)vcpu->vmx_vaddr_msr_area_host);
		    vcpu->vmcs.control_VM_exit_MSR_load_address=addr;
		}
		vcpu->vmcs.control_VM_exit_MSR_load_count= vmx_msr_area_msrs_count;

		//guest MSR load on entry, store on exit
		{
		    u64 addr = hva2spa((void*)vcpu->vmx_vaddr_msr_area_guest);
		    vcpu->vmcs.control_VM_entry_MSR_load_address=addr;
		}
		vcpu->vmcs.control_VM_entry_MSR_load_count=vmx_msr_area_msrs_count;
		{
		    u64 addr = hva2spa((void*)vcpu->vmx_vaddr_msr_area_guest);
		    vcpu->vmcs.control_VM_exit_MSR_store_address=addr;
		}
		vcpu->vmcs.control_VM_exit_MSR_store_count=vmx_msr_area_msrs_count;
	}


	vcpu->vmcs.control_pagefault_errorcode_mask  = 0x00000000;	//dont be concerned with
	vcpu->vmcs.control_pagefault_errorcode_match = 0x00000000; //guest page-faults
	vcpu->vmcs.control_exception_bitmap = 0;
	vcpu->vmcs.control_CR3_target_count = 0;

	//setup guest state
	if(vcpu->isbsp){
#ifdef __UEFI__
		xmhf_partition_arch_x86vmx_guestVMCS_UEFI(vcpu, &vmx_ctls);
#else /* !__UEFI__ */
		xmhf_partition_arch_x86vmx_guestVMCS_BIOS(vcpu);
#endif /* __UEFI__ */
	} else {
		xmhf_partition_arch_x86vmx_guestVMCS_INIT(vcpu);
	}

	//activate secondary processor controls
	_vmx_setctl_activate_secondary_controls(&vmx_ctls);

	//setup unrestricted guest
	_vmx_setctl_unrestricted_guest(&vmx_ctls);

	//allow INVPCID (used by Debian 11)
	if (_vmx_hasctl_enable_invpcid(&vcpu->vmx_caps)) {
		_vmx_setctl_enable_invpcid(&vmx_ctls);
	}

	//allow RDTSCP (used by Debian 11)
	if (_vmx_hasctl_enable_rdtscp(&vcpu->vmx_caps)) {
		_vmx_setctl_enable_rdtscp(&vmx_ctls);
	}

	//allow XSAVES/XRSTORS (provided by Dell OptiPlex 7050, used by Debian 11)
	if (_vmx_hasctl_enable_xsaves_xrstors(&vcpu->vmx_caps)) {
		_vmx_setctl_enable_xsaves_xrstors(&vmx_ctls);
		// Set the "XSS-exiting bitmap" to 0 to prevent VMEXIT
		vcpu->vmcs.control_XSS_exiting_bitmap = 0ULL;
	}

	if (_vmx_hasctl_use_msr_bitmaps(&vcpu->vmx_caps)) {
		_vmx_setctl_use_msr_bitmaps(&vmx_ctls);
		vmx_prepare_msr_bitmap(vcpu);
		vcpu->vmcs.control_MSR_Bitmaps_address = hva2spa(vmx_msr_bitmaps[vcpu->idx]);
	}

	//setup VMCS link pointer
	vcpu->vmcs.guest_VMCS_link_pointer = (u64)0xFFFFFFFFFFFFFFFFULL;

	//setup NMI intercept for core-quiescing
	_vmx_setctl_nmi_exiting(&vmx_ctls);
	_vmx_setctl_virtual_nmis(&vmx_ctls);
	vcpu->vmx_mhv_nmi_enable = true;
	vcpu->vmx_mhv_nmi_visited = 0;
	vcpu->vmx_mhv_nmi_handler_arg = SMPG_VMX_NMI_INJECT;
	vcpu->vmx_guest_nmi_cfg.guest_nmi_block = false;
	vcpu->vmx_guest_nmi_cfg.guest_nmi_pending = 0;
	vcpu->vmx_eptlock_reading = false;

	//write VMX controls to VMCS
	vcpu->vmcs.control_VMX_pin_based = vmx_ctls.pinbased_ctls;
	vcpu->vmcs.control_VMX_cpu_based = vmx_ctls.procbased_ctls;
	vcpu->vmcs.control_VMX_seccpu_based = vmx_ctls.procbased_ctls2;
	vcpu->vmcs.control_VM_exit_controls = vmx_ctls.exit_ctls;
	vcpu->vmcs.control_VM_entry_controls = vmx_ctls.entry_ctls;

#ifdef __NESTED_VIRTUALIZATION__
	xmhf_nested_arch_x86vmx_vcpu_init(vcpu);
#endif /* __NESTED_VIRTUALIZATION__ */

	//flush guest TLB to start with
	{
		u32 flags = MEMP_FLUSHTLB_EPTP | MEMP_FLUSHTLB_ENTRY | MEMP_FLUSHTLB_MT_ENTRY;
		xmhf_memprot_arch_x86vmx_flushmappings_localtlb(vcpu, flags);
	}
}



//---initVMCS - intialize VMCS for guest boot-----------------------------------
static void _vmx_initVMCS(VCPU *vcpu){
 	vmx_initunrestrictedguestVMCS(vcpu);
}


//---start a HVM----------------------------------------------------------------
static void _vmx_start_hvm(VCPU *vcpu, u32 vmcs_phys_addr){
  //clear VMCS
  if(!__vmx_vmclear((u64)vmcs_phys_addr)){
    printf("CPU(0x%02x): VMCLEAR failed, HALT!\n", vcpu->id);
    HALT();
  }
  printf("CPU(0x%02x): VMCLEAR success.\n", vcpu->id);


  //set VMCS revision id
 	*((u32 *)vcpu->vmx_vmcs_vaddr) = (u32)vcpu->vmx_msrs[INDEX_IA32_VMX_BASIC_MSR];

  //load VMPTR
  if(!__vmx_vmptrld((u64)vmcs_phys_addr)){
    printf("CPU(0x%02x): VMPTRLD failed, HALT!\n", vcpu->id);
    HALT();
  }
  printf("CPU(0x%02x): VMPTRLD success.\n", vcpu->id);

  //put VMCS to CPU
  xmhf_baseplatform_arch_x86vmx_putVMCS(vcpu);
  printf("CPU(0x%02x): VMWRITEs success.\n", vcpu->id);
  HALT_ON_ERRORCOND( vcpu->vmcs.guest_VMCS_link_pointer == 0xFFFFFFFFFFFFFFFFULL );

  {
    struct regs r;
    memset(&r, 0, sizeof(r));
    if (vcpu->isbsp) {
      /* For BSP, DL = boot drive number (usually EDX=0x80 for frist HDD). */
      r.edx = (u32) rpb->XtGuestOSBootDrive;
    } else {
      /* For AP, EDX=0x000n06xx (Intel's spec on processor state after INIT) */
      u32 _eax, _ebx, _ecx, _edx;
      cpuid(0x80000001U, &_eax, &_ebx, &_ecx, &_edx);
      r.edx = 0x00000600U | (0x000f0000U & _eax);
    }
    __vmx_vmentry_vmlaunch(&r);
    HALT_ON_ERRORCOND(0 && "__vmx_vmentry_vmlaunch() should never return");
  }
}




//initialize partition monitor for a given CPU
void xmhf_partition_arch_x86vmx_initializemonitor(VCPU *vcpu){

  //initialize VT
  _vmx_initVT(vcpu);


	#ifndef __XMHF_VERIFICATION__
   //clear VMCS
  memset((void *)&vcpu->vmcs, 0, sizeof(struct _vmx_vmcsfields));
   #endif

#ifndef __UEFI__
	//INT 15h E820 hook enablement for VMX unrestricted guest mode
	//note: this only happens for the BSP
	if(vcpu->isbsp){
		printf("CPU(0x%02x, BSP): initializing INT 15 hook for UG mode...\n", vcpu->id);
		_vmx_int15_initializehook(vcpu);
	}
#endif /* !__UEFI__ */

}



//setup guest OS state for the partition
void xmhf_partition_arch_x86vmx_setupguestOSstate(VCPU *vcpu){
		//initialize VMCS
		_vmx_initVMCS(vcpu);

}

//start executing the partition and guest OS
void xmhf_partition_arch_x86vmx_start(VCPU *vcpu){

#ifdef __XMHF_VERIFICATION_DRIVEASSERTS__
	//ensure that whenever a partition is started on a vcpu, we have extended paging
	//enabled and that the base points to the extended page tables we have initialized
	assert( vcpu->vmcs.control_EPT_pointer == (hva2spa((void*)vcpu->vmx_vaddr_ept_pml4_table) | 0x1E) );
	assert( (vcpu->vmcs.control_VMX_seccpu_based & (1U << VMX_SECPROCBASED_ENABLE_EPT)) );
	assert( vcpu->vmcs.host_RIP == 0xDEADBEEF);
#endif

#ifndef __XMHF_VERIFICATION__
    _vmx_start_hvm(vcpu, hva2spa((void*)vcpu->vmx_vmcs_vaddr));
	//we never get here, if we do, we just return and our caller is responsible
	//for halting the core as something really bad happened!
#endif

}

/*
 * Report error when VMLAUNCH or VMRESUME fails
 * When VMLAUNCH fails, is_resume = 0; VMRESUME fails, is_resume = 1.
 * When hardware returns VMfailInvalid, valid = 0;
 * When hardware returns VMfailValid, valid = 1;
 * When hardware performs invalid behavior, valid = 2.
 * This function never returns.
 */
void __vmx_vmentry_fail_callback(ulong_t is_resume, ulong_t valid)
{
	const char *inst_name = is_resume ? "VMRESUME" : "VMLAUNCH";
	VCPU *vcpu = _svm_and_vmx_getvcpu();
	switch (valid) {
	case 0:
		printf("CPU(0x%02x): %s error: VMCS pointer invalid? HALT!\n",
				vcpu->id, inst_name);
		break;
	case 1:
#ifdef __NESTED_VIRTUALIZATION__
		if (vcpu->vmx_nested_operation_mode == NESTED_VMX_MODE_NONROOT) {
			xmhf_nested_arch_x86vmx_handle_vmentry_fail(vcpu, is_resume);
			HALT_ON_ERRORCOND(0 && "Should not return");
		}
#endif /* __NESTED_VIRTUALIZATION__ */
		{
			unsigned long code;
			HALT_ON_ERRORCOND(__vmx_vmread(VMCSENC_info_vminstr_error, &code));
			printf("CPU(0x%02x): %s error; code=0x%lx.\n", vcpu->id, inst_name,
					code);
		}
		xmhf_baseplatform_arch_x86vmx_getVMCS(vcpu);
		xmhf_baseplatform_arch_x86vmx_dump_vcpu(vcpu);
		printf("CPU(0x%02x): HALT!\n", vcpu->id);
		break;
	default:
		printf("CPU(0x%02x): %s error: neither VMfailInvalid nor VMfailValid?"
				" HALT!\n", vcpu->id, inst_name);
		break;
	}
	HALT();
}

//set legacy I/O protection for the partition
void xmhf_partition_arch_x86vmx_legacyIO_setprot(VCPU *vcpu, u32 port, u32 size, u32 prottype){
	u8 *bit_vector = (u8 *)vcpu->vmx_vaddr_iobitmap;
	u32 byte_offset, bit_offset;
	u32 i;

	for(i=0; i < size; i++){
		byte_offset = (port+i) / 8;
		bit_offset = (port+i) % 8;
		if(prottype & PART_LEGACYIO_NOACCESS){
			bit_vector[byte_offset] |= (1 << bit_offset);
		}else{
			prottype = PART_LEGACYIO_READWRITE;
			bit_vector[byte_offset] &= ~((1 << bit_offset));
		}
	}
}
