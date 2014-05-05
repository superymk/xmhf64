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

// peh-x86vmx-main.c
// EMHF partition event-hub for Intel x86 vmx
// author: amit vasudevan (amitvasudevan@acm.org)
#include <xmhf-core.h> 
#include <xc-x86.h>
#include <xc-x86vmx.h>

extern struct regs xmhf_smpguest_arch_x86vmx_handle_guestmemoryreporting(context_desc_t context_desc, struct regs r);


static u32 _vmx_getregval(u32 gpr, struct regs r){

	  switch(gpr){
		case 0: return r.eax;
		case 1: return r.ecx;
		case 2: return r.edx;
		case 3: return r.ebx;
		case 4: return xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_RSP);
		case 5: return r.ebp;
		case 6: return r.esi;
		case 7: return r.edi;
		default:
			printf("\n%s: warning, invalid gpr value (%u): returning zero value", __FUNCTION__, gpr);
			return 0;
	}
}

//---intercept handler (CPUID)--------------------------------------------------
static struct regs _vmx_handle_intercept_cpuid(context_desc_t context_desc, struct regs r){
	asm volatile ("cpuid\r\n"
          :"=a"(r.eax), "=b"(r.ebx), "=c"(r.ecx), "=d"(r.edx)
          :"a"(r.eax), "c" (r.ecx));
    return r;
}

//------------------------------------------------------------------------------
// guest MSR r/w intercept handling
// HAL invokes NT kernel via SYSENTER if CPU supports it. However,
// regular apps using NTDLL will still use INT 2E if registry entry is not
// tweaked. So, we HAVE to emulate SYSENTER_CS/EIP/ESP to ensure that
// NT kernel doesnt panic with SESSION5_INITIALIZATION_FAILED!
//
// This took me nearly a month of disassembly into the HAL, 
// NTKERNEL and debugging to figure out..eh? 
//
// AMD SVM is neater, only
// when you ask for these MSR intercepts do they get stored and read from
// the VMCB. However, for Intel regardless they get stored and read from VMCS
// for the guest. So we need to have these intercepts bare minimum!!
// A line to this effect would have been much appreciated in the Intel manuals
// doh!!!
//------------------------------------------------------------------------------
  
//---intercept handler (WRMSR)--------------------------------------------------
static void _vmx_handle_intercept_wrmsr(context_desc_t context_desc, struct regs r){
	//printf("\nCPU(0x%02x): WRMSR 0x%08x", xc_cpu->cpuid, r.ecx);

	switch(r.ecx){
		case IA32_SYSENTER_CS_MSR:
			xmhfhw_cpu_x86vmx_vmwrite(VMCS_GUEST_SYSENTER_CS, r.eax);
			break;
		case IA32_SYSENTER_EIP_MSR:
			xmhfhw_cpu_x86vmx_vmwrite(VMCS_GUEST_SYSENTER_EIP, r.eax);
			break;
		case IA32_SYSENTER_ESP_MSR:
			xmhfhw_cpu_x86vmx_vmwrite(VMCS_GUEST_SYSENTER_ESP, r.eax);
			break;
		default:{
			asm volatile ("wrmsr\r\n"
          : //no outputs
          :"a"(r.eax), "c" (r.ecx), "d" (r.edx));	
			break;
		}
	} 
}

//---intercept handler (RDMSR)--------------------------------------------------
static struct regs _vmx_handle_intercept_rdmsr(context_desc_t context_desc, struct regs r){
	switch(r.ecx){
		case IA32_SYSENTER_CS_MSR:
			r.eax = xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_SYSENTER_CS);
			r.edx = 0;
			break;
		case IA32_SYSENTER_EIP_MSR:
			r.eax = xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_SYSENTER_EIP);
			r.edx = 0;
			break;
		case IA32_SYSENTER_ESP_MSR:
			r.eax = xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_SYSENTER_ESP);
			r.edx = 0;
			break;
		default:{
			asm volatile ("rdmsr\r\n"
          : "=a"(r.eax), "=d"(r.edx)
          : "c" (r.ecx));
			break;
		}
	}
	
	return r;
}


//---intercept handler (EPT voilation)----------------------------------
static void _vmx_handle_intercept_eptviolation(context_desc_t context_desc, u32 gpa, u32 gva, u32 errorcode, struct regs r __attribute__((unused))){

	xc_hypapp_handleintercept_hptfault(context_desc, gpa, gva,	(errorcode & 7));
}


//---intercept handler (I/O port access)----------------------------------------
static struct regs _vmx_handle_intercept_ioportaccess(context_desc_t context_desc, u32 access_size, u32 access_type, 
	u32 portnum, u32 stringio, struct regs r __attribute__((unused))){
	u32 app_ret_status = APP_TRAP_CHAIN;

	HALT_ON_ERRORCOND(!stringio);	//we dont handle string IO intercepts

	{
		xc_hypapp_arch_param_t xc_hypapp_arch_param;
		xc_hypapp_arch_param.operation = XC_HYPAPP_ARCH_PARAM_OPERATION_CBTRAP_IO;
		xc_hypapp_arch_param.param.cbtrapio.portnum = portnum;
		xc_hypapp_arch_param.param.cbtrapio.access_type = access_type;
		xc_hypapp_arch_param.param.cbtrapio.access_size = access_size;
		app_ret_status=xc_hypapp_handleintercept_trap(context_desc, xc_hypapp_arch_param);
	}

	if(app_ret_status == APP_TRAP_CHAIN){
		if(access_type == IO_TYPE_OUT){
			if( access_size== IO_SIZE_BYTE)
					outb((u8)r.eax, portnum);
			else if (access_size == IO_SIZE_WORD)
					outw((u16)r.eax, portnum);
			else if (access_size == IO_SIZE_DWORD)
					outl((u32)r.eax, portnum);	
		}else{
			if( access_size== IO_SIZE_BYTE){
					r.eax &= 0xFFFFFF00UL;	//clear lower 8 bits
					r.eax |= (u8)inb(portnum);
			}else if (access_size == IO_SIZE_WORD){
					r.eax &= 0xFFFF0000UL;	//clear lower 16 bits
					r.eax |= (u16)inw(portnum);
			}else if (access_size == IO_SIZE_DWORD){
					r.eax = (u32)inl(portnum);	
			}
		}
	}

	return r;
}


//---CR0 access handler-------------------------------------------------
static void vmx_handle_intercept_cr0access_ug(context_desc_t context_desc, struct regs r, u32 gpr, u32 tofrom){
	u32 cr0_value;
	
	HALT_ON_ERRORCOND(tofrom == VMX_CRX_ACCESS_TO);
	
	cr0_value = _vmx_getregval(gpr, r);

	xmhfhw_cpu_x86vmx_vmwrite(VMCS_CONTROL_CR0_SHADOW, cr0_value);
	xmhfhw_cpu_x86vmx_vmwrite(VMCS_GUEST_CR0, (cr0_value & ~(CR0_CD | CR0_NW)));
	
	//we need to flush logical processor VPID mappings as we emulated CR0 load above
	__vmx_invvpid(VMX_INVVPID_SINGLECONTEXT, 1, 0);
}

//---CR4 access handler---------------------------------------------------------
static void vmx_handle_intercept_cr4access_ug(context_desc_t context_desc, struct regs r, u32 gpr, u32 tofrom){
  if(tofrom == VMX_CRX_ACCESS_TO){
	u32 cr4_proposed_value;
	
	cr4_proposed_value = _vmx_getregval(gpr, r);
	
	//we need to flush logical processor VPID mappings as we emulated CR4 load above
	__vmx_invvpid(VMX_INVVPID_SINGLECONTEXT, 1, 0);
  }
}

//---XSETBV intercept handler-------------------------------------------
static void _vmx_handle_intercept_xsetbv(context_desc_t context_desc, struct regs r){
	u64 xcr_value;
	
	xcr_value = ((u64)r.edx << 32) + (u64)r.eax;
	
	if(r.ecx != XCR_XFEATURE_ENABLED_MASK){
			printf("\n%s: unhandled XCR register %u", __FUNCTION__, r.ecx);
			HALT();
	}

	//XXX: TODO: check for invalid states and inject GP accordingly
	printf("\n%s: xcr_value=%llx", __FUNCTION__, xcr_value);
	
	//set XCR with supplied value
	xsetbv(XCR_XFEATURE_ENABLED_MASK, xcr_value);
}						
			
static void _vmx_propagate_cpustate_guestx86gprs(context_desc_t context_desc, struct regs x86gprs){
	xc_hypapp_arch_param_t ap;

	ap.param.cpugprs = x86gprs;
	ap.operation = XC_HYPAPP_ARCH_PARAM_OPERATION_CPUSTATE_CPUGPRS;
	xc_api_cpustate_set(context_desc, ap);
}

//====================================================================================

static void _vmx_intercept_handler(context_desc_t context_desc, struct regs x86gprs){
	xc_hypapp_arch_param_t ap;
	xc_hypapp_arch_param_x86vmx_cpustate_inforegs_t inforegs;
	
	ap = xc_api_cpustate_get(context_desc, XC_HYPAPP_ARCH_PARAM_OPERATION_CPUSTATE_INFOREGS);
	inforegs = ap.param.inforegs;
	
	
	//sanity check for VM-entry errors
	if( inforegs.info_vmexit_reason & 0x80000000UL ){
		printf("\nVM-ENTRY error: reason=0x%08x, qualification=0x%016llx", 
			inforegs.info_vmexit_reason, inforegs.info_exit_qualification);
		HALT();
	}

	//make sure we have no nested events
	if( inforegs.info_idt_vectoring_information & 0x80000000){
		printf("\nCPU(0x%02x): HALT; Nested events unhandled with hwp:0x%08x",
			context_desc.cpu_desc.cpu_index, inforegs.info_idt_vectoring_information);
		HALT();
	}

	//handle intercepts
	switch(inforegs.info_vmexit_reason){
		//--------------------------------------------------------------
		//xmhf-core and hypapp intercepts
		//--------------------------------------------------------------
		
		case VMX_VMEXIT_VMCALL:{
			//if INT 15h E820 hypercall, then let the xmhf-core handle it
			if(xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_CS_BASE) == (VMX_UG_E820HOOK_CS << 4) &&
				xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_RIP) == VMX_UG_E820HOOK_IP){
	
				//we need to be either in real-mode or in protected
				//mode with paging and EFLAGS.VM bit set (virtual-8086 mode)
				HALT_ON_ERRORCOND( !(xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_CR0) & CR0_PE)  ||
					( (xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_CR0) & CR0_PE) && (xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_CR0) & CR0_PG) &&
						(xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_RFLAGS) & EFLAGS_VM)  ) );
				x86gprs = xmhf_smpguest_arch_x86vmx_handle_guestmemoryreporting(context_desc, x86gprs);
				
			}else{	//if not E820 hook, give hypapp a chance to handle the hypercall
				{
					u64 hypercall_id = (u64)x86gprs.eax;
					u64 hypercall_param = ((u64)x86gprs.edx << 32) | x86gprs.ecx;
	
					if( xc_hypapp_handlehypercall(context_desc, hypercall_id, hypercall_param) != APP_SUCCESS){
						printf("\nCPU(0x%02x): error(halt), unhandled hypercall 0x%08x!", context_desc.cpu_desc.cpu_index, x86gprs.eax);
						HALT();
					}
				}
				xmhfhw_cpu_x86vmx_vmwrite(VMCS_GUEST_RIP, (xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_RIP)+3) );
			}
		}
		_vmx_propagate_cpustate_guestx86gprs(context_desc, x86gprs);
		break;

		case VMX_VMEXIT_IOIO:{
			u32 access_size, access_type, portnum, stringio;
			
			access_size = inforegs.info_exit_qualification & 0x00000007UL;
			access_type = ( inforegs.info_exit_qualification & 0x00000008UL) >> 3;
			portnum =  ( inforegs.info_exit_qualification & 0xFFFF0000UL) >> 16;
			stringio = ( inforegs.info_exit_qualification & 0x00000010UL) >> 4;

			x86gprs = _vmx_handle_intercept_ioportaccess(context_desc, access_size, access_type, portnum, stringio, x86gprs);
			xmhfhw_cpu_x86vmx_vmwrite(VMCS_GUEST_RIP, (xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_RIP)+inforegs.info_vmexit_instruction_length) );
		}
		_vmx_propagate_cpustate_guestx86gprs(context_desc, x86gprs);
		break;

		case VMX_VMEXIT_EPT_VIOLATION:{
			u32 errorcode, gpa, gva;

			errorcode = inforegs.info_exit_qualification;
			gpa = inforegs.info_guest_paddr_full;
			gva = inforegs.info_guest_linear_address;

			_vmx_handle_intercept_eptviolation(context_desc, gpa, gva, errorcode, x86gprs);
		}
		_vmx_propagate_cpustate_guestx86gprs(context_desc, x86gprs);
		break;  

		case VMX_VMEXIT_INIT:{

			printf("\n***** VMEXIT_INIT xc_hypapp_handleshutdown\n");
			xc_hypapp_handleshutdown(context_desc);      
			printf("\nCPU(0x%02x): Fatal, xc_hypapp_handleshutdown returned. Halting!", context_desc.cpu_desc.cpu_index);
			HALT();
		}
		break;

		//--------------------------------------------------------------
		//xmhf-core only intercepts
		//--------------------------------------------------------------

 		case VMX_VMEXIT_CRX_ACCESS:{
			u32 tofrom, gpr, crx; 
			crx=(u32) ((u64)inforegs.info_exit_qualification & 0x000000000000000FULL);
			gpr=
			 (u32) (((u64)inforegs.info_exit_qualification & 0x0000000000000F00ULL) >> (u64)8);
			tofrom = 
			(u32) (((u64)inforegs.info_exit_qualification & 0x0000000000000030ULL) >> (u64)4); 

			if ( ((int)gpr >=0) && ((int)gpr <= 7) ){
				switch(crx){
					case 0x0: //CR0 access
						vmx_handle_intercept_cr0access_ug(context_desc, x86gprs, gpr, tofrom);	
						break;
					
					case 0x4: //CR4 access
						vmx_handle_intercept_cr4access_ug(context_desc, x86gprs, gpr, tofrom);	
						break;
				
					default:
						printf("\nunhandled crx, halting!");
						HALT();
				}
			  	xmhfhw_cpu_x86vmx_vmwrite(VMCS_GUEST_RIP, (xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_RIP)+inforegs.info_vmexit_instruction_length) );

			}else{
				printf("\n[%02x]%s: invalid gpr value (%u). halting!", context_desc.cpu_desc.cpu_index,
					__FUNCTION__, gpr);
				HALT();
			}
		}
		break;	

 		case VMX_VMEXIT_RDMSR:
			x86gprs = _vmx_handle_intercept_rdmsr(context_desc, x86gprs);
			xmhfhw_cpu_x86vmx_vmwrite(VMCS_GUEST_RIP, (xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_RIP)+inforegs.info_vmexit_instruction_length) );
			_vmx_propagate_cpustate_guestx86gprs(context_desc, x86gprs);
			break;
			
		case VMX_VMEXIT_WRMSR:
			_vmx_handle_intercept_wrmsr(context_desc, x86gprs);
			xmhfhw_cpu_x86vmx_vmwrite(VMCS_GUEST_RIP, (xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_RIP)+inforegs.info_vmexit_instruction_length) );
			break;
			
		case VMX_VMEXIT_CPUID:
			x86gprs = _vmx_handle_intercept_cpuid(context_desc, x86gprs);
			xmhfhw_cpu_x86vmx_vmwrite(VMCS_GUEST_RIP, (xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_RIP)+inforegs.info_vmexit_instruction_length) );
			_vmx_propagate_cpustate_guestx86gprs(context_desc, x86gprs);
			break;

		case VMX_VMEXIT_TASKSWITCH:{
			u32 idt_v = inforegs.info_idt_vectoring_information & VECTORING_INFO_VALID_MASK;
			u32 type = inforegs.info_idt_vectoring_information & VECTORING_INFO_TYPE_MASK;
			u32 reason = inforegs.info_exit_qualification >> 30;
			u16 tss_selector = (u16)inforegs.info_exit_qualification;
			
			if(reason == TASK_SWITCH_GATE && type == INTR_TYPE_NMI){
				printf("\nCPU(0x%02x): NMI received (MP guest shutdown?)", context_desc.cpu_desc.cpu_index);
				xc_hypapp_handleshutdown(context_desc);      
				printf("\nCPU(0x%02x): warning, xc_hypapp_handleshutdown returned!", context_desc.cpu_desc.cpu_index);
				printf("\nCPU(0x%02x): HALTING!", context_desc.cpu_desc.cpu_index);
				HALT();
			}else{
				printf("\nCPU(0x%02x): Unhandled Task Switch. Halt!", context_desc.cpu_desc.cpu_index);
				printf("\n	idt_v=0x%08x, type=0x%08x, reason=0x%08x, tsssel=0x%04x",
					idt_v, type, reason, tss_selector); 
			}
			HALT();
		}
		break;

		case VMX_VMEXIT_XSETBV:{
			_vmx_handle_intercept_xsetbv(context_desc, x86gprs);
			//skip the emulated XSETBV instruction
			xmhfhw_cpu_x86vmx_vmwrite(VMCS_GUEST_RIP, (xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_RIP)+inforegs.info_vmexit_instruction_length) );
		}
		break;

		case VMX_VMEXIT_SIPI:{
			u32 sipivector = (u8)inforegs.info_exit_qualification;
			printf("\nCPU(%02x): SIPI vector=0x%08x", context_desc.cpu_desc.cpu_index, sipivector);
			xmhfhw_cpu_x86vmx_vmwrite(VMCS_GUEST_CS_SELECTOR, ((sipivector * PAGE_SIZE_4K) >> 4));
			xmhfhw_cpu_x86vmx_vmwrite(VMCS_GUEST_CS_BASE, (sipivector * PAGE_SIZE_4K));
			xmhfhw_cpu_x86vmx_vmwrite(VMCS_GUEST_RIP, 0x0ULL);
			xmhfhw_cpu_x86vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, 0);	//active
		}
		break;

    
		default:{
			printf("\nCPU(0x%02x): Unhandled intercept: 0x%08x", context_desc.cpu_desc.cpu_index, (u32)inforegs.info_vmexit_reason);
			printf("\n	CPU(0x%02x): EFLAGS=0x%08x", context_desc.cpu_desc.cpu_index, (u32)xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_RFLAGS));
			printf("\n	SS:ESP =0x%04x:0x%08x", (u16)xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_SS_SELECTOR), (u32)xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_RSP));
			printf("\n	CS:EIP =0x%04x:0x%08x", (u16)xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_CS_SELECTOR), (u32)xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_RIP));
			printf("\n	IDTR base:limit=0x%08x:0x%04x", (u32)xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_IDTR_BASE),
					(u16)xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_IDTR_LIMIT));
			printf("\n	GDTR base:limit=0x%08x:0x%04x", (u32)xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_GDTR_BASE),
					(u16)xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_GDTR_LIMIT));
			HALT();
		}		
	} //end switch((u32)xc_cpu->vmcs.info_vmexit_reason)
	

 	//check and clear guest interruptibility state
	if(xmhfhw_cpu_x86vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY) != 0){
		xmhfhw_cpu_x86vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY, 0);
	}


#ifdef __XMHF_VERIFICATION_DRIVEASSERTS__
	//ensure that whenever a partition is resumed on a xc_cpu, we have extended paging
	//enabled and that the base points to the extended page tables we have initialized
	assert( (xc_cpu->vmcs.control_VMX_seccpu_based & 0x2) );
	assert( (xc_cpu->vmcs.control_EPT_pointer_high == 0) && (xc_cpu->vmcs.control_EPT_pointer_full == (hva2spa((void*)xc_cpu->vmx_vaddr_ept_pml4_table) | 0x1E)) );
#endif	

	
}




//---hvm_intercept_handler------------------------------------------------------
void xmhf_parteventhub_arch_x86vmx_entry(void) __attribute__((naked)){
		//step-1: save all CPU GPRs
		asm volatile ("pushal\r\n");
		
		//step-2: grab xc_cpu_t *
		//asm volatile ("movl 32(%esp), %esi\r\n");
			      
		//step-3: get hold of pointer to saved GPR on stack
		asm volatile ("movl %esp, %eax\r\n");

		//step-4: invoke "C" event handler
		//1st argument is xc_cpu_t * followed by pointer to saved GPRs
		asm volatile ("pushl %eax\r\n");
		//asm volatile ("pushl %esi\r\n");
		asm volatile ("call xmhf_partition_eventhub_arch_x86vmx\r\n");
		//asm volatile ("addl $0x08, %esp\r\n");
		asm volatile ("addl $0x04, %esp\r\n");

		//step-5; restore all CPU GPRs
		asm volatile ("popal\r\n");

		//resume partition
		asm volatile ("vmresume\r\n");
              
		//if we get here then vm resume failed, just bail out with a BP exception 
		asm volatile ("int $0x03\r\n");
		asm volatile ("hlt\r\n");
}


//void xmhf_partition_eventhub_arch_x86vmx(xc_cpu_t *xc_cpu, struct regs *cpugprs){
void xmhf_partition_eventhub_arch_x86vmx(struct regs *cpugprs){
	static u32 _xc_partition_eventhub_lock = 1; 
	xc_hypapp_arch_param_t cpustateparams;
	struct regs x86gprs;
	context_desc_t context_desc;
	//xc_cpu_t *xc_cpu;
	//u32 cpu_index;

	
#ifndef __XMHF_VERIFICATION__
	//handle cpu quiescing
	if(xmhfhw_cpu_x86vmx_vmread(VMCS_INFO_VMEXIT_REASON) == VMX_VMEXIT_EXCEPTION){
		if ( (xmhfhw_cpu_x86vmx_vmread(VMCS_INFO_VMEXIT_INTERRUPT_INFORMATION) & INTR_INFO_VECTOR_MASK) == 0x02 ) {
			xmhf_smpguest_arch_eventhandler_nmiexception(cpugprs);
			return;
		}
	}
#endif //__XMHF_VERIFICATION__

	//serialize
    spin_lock(&_xc_partition_eventhub_lock);

	context_desc = xc_api_partition_getcontextdesc(xmhf_baseplatform_arch_x86_getcpulapicid());
	if(context_desc.cpu_desc.cpu_index == XC_PARTITION_INDEX_INVALID || context_desc.partition_desc.partition_index == XC_PARTITION_INDEX_INVALID){
		printf("\n%s: invalid partition/cpu context. Halting!\n", __FUNCTION__);
		HALT();
	}
	//xc_cpu = &g_xc_cpu[context_desc.cpu_desc.cpu_index];
	
	//set cpu gprs state based on cpugprs
	cpustateparams = xc_api_cpustate_get(context_desc, XC_HYPAPP_ARCH_PARAM_OPERATION_CPUSTATE_CPUGPRS);
	x86gprs.edi = cpustateparams.param.cpugprs.edi = cpugprs->edi;
	x86gprs.esi = cpustateparams.param.cpugprs.esi = cpugprs->esi;
	x86gprs.ebp = cpustateparams.param.cpugprs.ebp = cpugprs->ebp;
	x86gprs.esp = cpustateparams.param.cpugprs.esp;	//guest ESP is stored in the VMCS and is returned by xc_api_cpustate_get above
	x86gprs.ebx = cpustateparams.param.cpugprs.ebx = cpugprs->ebx;
	x86gprs.edx = cpustateparams.param.cpugprs.edx = cpugprs->edx;
	x86gprs.ecx = cpustateparams.param.cpugprs.ecx = cpugprs->ecx;
	x86gprs.eax = cpustateparams.param.cpugprs.eax = cpugprs->eax;
	cpustateparams.operation = XC_HYPAPP_ARCH_PARAM_OPERATION_CPUSTATE_CPUGPRS;
	xc_api_cpustate_set(context_desc, cpustateparams);

	_vmx_intercept_handler(context_desc, x86gprs);
	
	cpustateparams = xc_api_cpustate_get(context_desc, XC_HYPAPP_ARCH_PARAM_OPERATION_CPUSTATE_CPUGPRS);
	cpugprs->edi = cpustateparams.param.cpugprs.edi;
	cpugprs->esi = cpustateparams.param.cpugprs.esi;
	cpugprs->ebp = cpustateparams.param.cpugprs.ebp;
	//cpugprs->esp, guest ESP is loaded from VMCS which is set using xc_api_cpustate_set
	cpugprs->ebx = cpustateparams.param.cpugprs.ebx;
	cpugprs->edx = cpustateparams.param.cpugprs.edx;
	cpugprs->ecx = cpustateparams.param.cpugprs.ecx;
	cpugprs->eax = cpustateparams.param.cpugprs.eax;

	//end serialization and resume partition
    spin_unlock(&_xc_partition_eventhub_lock);
}






