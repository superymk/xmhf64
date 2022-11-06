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

// EMHF app. callback declarations
// author: amit vasudevan (amitvasudevan@acm.org)

#ifndef __EMHF_APP_H__
#define __EMHF_APP_H__

#ifndef __ASSEMBLY__

//----------------------------------------------------------------------
// EMHF application related declarations
//----------------------------------------------------------------------

//generic catch-all app return codes
#define APP_SUCCESS     		(0x1)
#define APP_ERROR				(0x0)

//emhf app constant definitions
#define APP_IOINTERCEPT_CHAIN   0xA0
#define APP_IOINTERCEPT_SKIP    0xA1
#define APP_INIT_SUCCESS        0x0
#define APP_INIT_FAIL           0xFF


//application parameter block
//for now it holds the bootsector and optional module info loaded by GRUB
//eventually this will be generic enough for both boot-time and dynamic loading
//capabilities
typedef struct {
  hva_t bootsector_ptr;
  hva_t bootsector_size;
  hva_t optionalmodule_ptr;
  hva_t optionalmodule_size;
  hva_t runtimephysmembase;
  u8 boot_drive;
  char cmdline[1024];
} APP_PARAM_BLOCK;


//EMHF application callbacks

/*
 * Called by all CPUs when XMHF boots.
 *
 * Hypapp should return APP_INIT_SUCCESS if hypapp initialization is successful.
 * Otherwise hypapp should return APP_INIT_FAIL (XMHF will halt).
 *
 * When this function is called, other CPUs are NOT quiesced.
 */
extern u32 xmhf_app_main(VCPU *vcpu, APP_PARAM_BLOCK *apb);

/*
 * Called when the guest accesses some I/O port that is configured to be
 * intercepted using the I/O bitmap.
 *
 * portnum: I/O port number accessed (0 - 0xffff inclusive)
 * access_type: IO_TYPE_IN or IO_TYPE_OUT
 * access_size: IO_SIZE_BYTE or IO_SIZE_WORD or IO_SIZE_DWORD
 *
 * Hypapp should return APP_IOINTERCEPT_SKIP if the I/O port access is handled.
 * Otherwise hypapp should return APP_IOINTERCEPT_CHAIN (XMHF will perform the
 * access in hypervisor mode).
 *
 * When this function is called, other CPUs may or may not be quiesced. This is
 * configured using __XMHF_QUIESCE_CPU_IN_GUEST_MEM_PIO_TRAPS__.
 */
extern u32 xmhf_app_handleintercept_portaccess(VCPU *vcpu, struct regs *r,
                                               u32 portnum, u32 access_type,
                                               u32 access_size);

/*
 * Called when the guest accesses invalid memory in NPT / EPT.
 *
 * In nested virtualization, this function is called when EPT02 violation is
 * due to EPT01 violation. L1 will handle EPT02 violation due to EPT12
 * violation.
 *
 * gpa: guest physical address accessed
 * gva: guest virtual address accessed
 * violationcode: platform specific reasion of NPT / EPT violation
 *
 * When this function is called, other CPUs may or may not be quiesced. This is
 * configured using __XMHF_QUIESCE_CPU_IN_GUEST_MEM_PIO_TRAPS__.
 */
extern u32 xmhf_app_handleintercept_hwpgtblviolation(VCPU *vcpu, struct regs *r,
                                                     gpa_t gpa, gva_t gva,
                                                     u64 violationcode);

/*
 * Called when the guest tries to shutdown / restart.
 *
 * Hypapp should call xmhf_baseplatform_reboot() to perform the restart.
 *
 * When this function is called, other CPUs are NOT quiesced.
 * XXX: this is leading to known vulnerabilities of XMHF.
 */
extern void xmhf_app_handleshutdown(VCPU *vcpu, struct regs *r);

/*
 * Called when the guest tries to perform VMCALL / VMMCALL.
 *
 * In nested virtualization, this function is called when r->eax is within
 * range [VMX_HYPAPP_L2_VMCALL_MIN, VMX_HYPAPP_L2_VMCALL_MAX] (inclusive).
 * Otherwise the hyper call is handled by L1.
 *
 * Hypapp should return APP_SUCCESS if hyper call is handled. Otherwise hypapp
 * should return APP_ERROR (XMHF will halt).
 *
 * When this function is called, other CPUs are quiesced.
 */
extern u32 xmhf_app_handlehypercall(VCPU *vcpu, struct regs *r);

/*
 * Called when the guest tries to modify MTRR.
 *
 * Hypapp should return APP_SUCCESS if MTRR can be modified (for VMX, XMHF will
 * modify MTRR). Otherwise hypapp should return APP_ERROR (XMHF will halt).
 *
 * When this function is called, other CPUs are NOT quiesced.
 */
extern u32 xmhf_app_handlemtrr(VCPU *vcpu, u32 msr, u64 val);

/*
 * Called when the guest executes CPUID.
 *
 * The intention is to allow the guest to detect presence of the hypapp.
 *
 * Before calling this function, XMHF already performs CPUID and updates r. The
 * old EAX from the guest is in fn.
 *
 * TODO: modify interface to let hypapp return whether CPUID is handled.
 *
 * When this function is called, other CPUs are NOT quiesced.
 */
extern void xmhf_app_handlecpuid(VCPU *vcpu, struct regs *r, uint32_t fn);

#endif	//__ASSEMBLY__

#endif	// __EMHF_APP_H__
