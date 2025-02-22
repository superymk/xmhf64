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

// EMHF DMA protection component implementation
// author: amit vasudevan (amitvasudevan@acm.org)

#include <xmhf.h>

//return size (in bytes) of the memory buffer required for
//DMA protection for a given physical memory limit
u32 xmhf_dmaprot_getbuffersize(u64 physical_memory_limit){
	return xmhf_dmaprot_arch_getbuffersize(physical_memory_limit);
}

//"normal" DMA protection initialization to setup required
//structures for DMA protection
//return 1 on success 0 on failure
u32 xmhf_dmaprot_initialize(spa_t protectedbuffer_paddr, hva_t protectedbuffer_vaddr, size_t protectedbuffer_size){
	return xmhf_dmaprot_arch_initialize(protectedbuffer_paddr, protectedbuffer_vaddr, protectedbuffer_size);
}

// Call memprot to protect DRHD pages. Should be called by each CPU after
// xmhf_dmaprot_initialize().
void xmhf_dmaprot_protect_drhd(VCPU *vcpu){
	xmhf_dmaprot_arch_protect_drhd(vcpu);
}

// Enable the DMA protection HW
// [NOTE] This function must be separated from <xmhf_dmaprot_initialize>. Otherwise, misconfigured devices can have a 
// chance to modify XMHF binary between the function <xmhf_dmaprot_initialize> and <xmhf_dmaprot_protect> inside 
// <xmhf_runtime_entry>
//return 1 on success 0 on failure
u32 xmhf_dmaprot_enable(spa_t protectedbuffer_paddr,
	hva_t protectedbuffer_vaddr, size_t protectedbuffer_size)
{
    return xmhf_dmaprot_arch_enable(protectedbuffer_paddr, protectedbuffer_vaddr, protectedbuffer_size);
}

//DMA protect a given region of memory, start_paddr is
//assumed to be page aligned physical memory address
void xmhf_dmaprot_protect(spa_t start_paddr, size_t size){
	return xmhf_dmaprot_arch_protect(start_paddr, size);
}

//DMA unprotect a given region of memory, start_paddr is
//assumed to be page aligned physical memory address
void xmhf_dmaprot_unprotect(spa_t start_paddr, size_t size){
	return xmhf_dmaprot_arch_unprotect(start_paddr, size);
}

void xmhf_dmaprot_invalidate_cache(void)
{
	xmhf_dmaprot_arch_invalidate_cache();
}
