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

// Capture device write-only transfer descriptors (e.g., the CRCR register of XHCI).
// author: Miao Yu (superymk@cmu.edu)

#include <xmhf.h>
#include <arch/x86/xmhf-device.h>



void xmhf_gpa_changemapping(VCPU *vcpu, gpa_t dev_reg_gpaddr, gpa_t new_dev_reg_gpaddr, u64 mapflag)
{
#ifndef __XMHF_VERIFICATION__
	u64 *pts;
	u64 gpfn;
	u64 value;

	pts = (u64 *)vcpu->vmx_vaddr_ept_p_tables;
	gpfn = dev_reg_gpaddr / PAGE_SIZE_4K;
	value = (u64)new_dev_reg_gpaddr | mapflag;

	pts[gpfn] = value;

	//   xmhf_memprot_arch_x86vmx_flushmappings_localtlb(vcpu, MEMP_FLUSHTLB_ENTRY);
	xmhf_memprot_arch_flushmappings_localtlb(vcpu, MEMP_FLUSHTLB_ENTRY);
#endif //__XMHF_VERIFICATION__
}