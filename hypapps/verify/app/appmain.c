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

// appmain.c
// xmhf application main module (for xmhf-core verification)
// author: amit vasudevan (amitvasudevan@acm.org)

#include <xmhf.h>

#define V_HYPERCALL		0xDEADBEEF


// application main
u32 xmhf_app_main(VCPU *vcpu, APP_PARAM_BLOCK *apb){
  (void)apb;	//unused
  printf("\nCPU(0x%02x): XMHF core verification hypapp!", vcpu->id);
  return APP_INIT_SUCCESS;  //successful
}

u32 v_hypercall_handler(VCPU *vcpu, struct regs *r){

	//invoke setprot to set memory protections
	//assume that gpa and prottype are passed using GPR
	//ECX and EDX respectively (under attacker's control)
	{
		#ifndef __XMHF_VERIFICATION__
			u32 gpa=r->ecx;
			u32 prottype=r->edx;
		#else
			u32 gpa=nondet_u32();
			u32 prottype=nondet_u32();
		#endif

		if( ((gpa < rpb->XtVmmRuntimePhysBase) ||
		    (gpa >= (rpb->XtVmmRuntimePhysBase + rpb->XtVmmRuntimeSize)))
			&&
			( (prottype > 0) &&
	          (prottype <= MEMP_PROT_MAXVALUE)
	        )
			&&
			(	(prottype == MEMP_PROT_NOTPRESENT) ||
				((prottype & MEMP_PROT_PRESENT) && (prottype & MEMP_PROT_READONLY) && (prottype & MEMP_PROT_EXECUTE)) ||
				((prottype & MEMP_PROT_PRESENT) && (prottype & MEMP_PROT_READWRITE) && (prottype & MEMP_PROT_EXECUTE)) ||
				((prottype & MEMP_PROT_PRESENT) && (prottype & MEMP_PROT_READONLY) && (prottype & MEMP_PROT_NOEXECUTE)) ||
				((prottype & MEMP_PROT_PRESENT) && (prottype & MEMP_PROT_READWRITE) && (prottype & MEMP_PROT_NOEXECUTE))
			)
		  ){
			//xmhf_memprot_setprot(&vcpu, gpa, MEMP_PROT_PRESENT | MEMP_PROT_READWRITE | MEMP_PROT_EXECUTE);
			xmhf_memprot_setprot(vcpu, gpa, prottype);
		}else{
			printf("\nSecurity Exception: Trying to set protections on EMHF memory regions, Halting!");
			HALT();
		}
	}


		return APP_SUCCESS;
}

u32 xmhf_app_handlehypercall(VCPU *vcpu, struct regs *r){
	struct _svm_vmcbfields *vmcb = (struct _svm_vmcbfields *)vcpu->vmcb_vaddr_ptr;
	u32 status=APP_SUCCESS;
	u32 call_id;

	if(vcpu->cpu_vendor == CPU_VENDOR_AMD)
		call_id = (u32)vmcb->rax;
	else
		call_id = r->eax;


	switch(call_id){

		case V_HYPERCALL:{
			status=v_hypercall_handler(vcpu, r);
		}
		break;

		default:
			printf("\nCPU(0x%02x): unsupported hypercall (0x%08x)!!",
			  vcpu->id, call_id);
			status=APP_ERROR;
			break;
	}

	return status;
}

//returns APP_SUCCESS if we allow EPT to change in response to MTRR
u32 xmhf_app_handlemtrr(VCPU *vcpu, u32 msr, u64 val) {
	(void) vcpu;
	(void) msr;
	(void) val;
	// TODO: This hypapp needs to be reviewed to decide when MTRRs can change
	return APP_ERROR;
}

//handles XMHF shutdown callback
//note: should not return
void xmhf_app_handleshutdown(VCPU *vcpu, struct regs *r){
	(void)r; //unused
	xmhf_baseplatform_reboot(vcpu);
}

void xmhf_app_handle_mhv_halt(VCPU *vcpu, struct regs *r)
{
    (void)vcpu;
    (void)r;
}

//handles CPUID invokation
//for now allow default behavior
u32 xmhf_app_handlecpuid(VCPU *vcpu, struct regs *r)
{
	(void)vcpu;(void)r;
	return APP_CPUID_CHAIN;
}

u32 xmhf_app_handle_external_interrupt(VCPU *vcpu, struct regs *r)
{
  // XMHF should not call this function because this hypapp does not set
  // "External-interrupt exiting"
  (void)vcpu;
  (void)r;
  HALT_ON_ERRORCOND(0 && "XMHF should not call this function");
}

u32 xmhf_app_handle_interrupt_window(VCPU *vcpu, struct regs *r)
{
  // XMHF should not call this function because this hypapp does not set
  // "Interrupt-window exiting"
  (void)vcpu;
  (void)r;
  HALT_ON_ERRORCOND(0 && "XMHF should not call this function");
}

#ifdef __NESTED_VIRTUALIZATION__
u32 xmhf_app_handle_nest_entry(VCPU *vcpu, struct regs *r)
{
  (void)vcpu;
  (void)r;
  return APP_SUCCESS;
}

u32 xmhf_app_handle_nest_exit(VCPU *vcpu, struct regs *r)
{
  (void)vcpu;
  (void)r;
  return APP_SUCCESS;
}
#endif /* __NESTED_VIRTUALIZATION__ */

//handles h/w pagetable violations
//for now this always returns APP_SUCCESS
u32 xmhf_app_handleintercept_hwpgtblviolation(VCPU *vcpu,
      struct regs *r,
      u64 gpa, u64 gva, u64 violationcode){
	u32 status = APP_SUCCESS;

	(void)vcpu; //unused
	(void)r; //unused
	(void)gpa; //unused
	(void)gva; //unused
	(void)violationcode; //unused

	return status;
}


//handles i/o port intercepts
//returns either APP_IOINTERCEPT_SKIP or APP_IOINTERCEPT_CHAIN
u32 xmhf_app_handleintercept_portaccess(VCPU *vcpu, struct regs *r,
  u32 portnum, u32 access_type, u32 access_size){
	(void)vcpu; //unused
	(void)r; //unused
	(void)portnum; //unused
	(void)access_type; //unused
	(void)access_size; //unused

 	return APP_IOINTERCEPT_CHAIN;
}
