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
 * This file is part of the EMHF historical reference
 * codebase, and is released under the terms of the
 * GNU General Public License (GPL) version 2.
 * Please see the LICENSE file for details.
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
// AMD SVM arch. backend implementation
// author: amit vasudevan (amitvasudevan@acm.org)

#include <emhf.h> 

//----------------------------------------------------------------------
// local (static) support function forward declarations
static void _svm_nptinitialize(u32 npt_pdpt_base, u32 npt_pdts_base, u32 npt_pts_base);

//======================================================================
// global interfaces (functions) exported by this component

// initialize memory protection structures for a given core (vcpu)
void emhf_memprot_arch_svm_initialize(VCPU *vcpu){
	struct vmcb_struct *vmcb = (struct vmcb_struct *)vcpu->vmcb_vaddr_ptr;
	
	ASSERT(vcpu->cpu_vendor == CPU_VENDOR_AMD);
	
	_svm_nptinitialize(vcpu->npt_vaddr_ptr, vcpu->npt_vaddr_pdts, vcpu->npt_vaddr_pts);
	vmcb->h_cr3 = __hva2spa__((void*)vcpu->npt_vaddr_ptr);
	vmcb->np_enable |= (1ULL << NP_ENABLE);
	vmcb->guest_asid = vcpu->npt_asid;
}

//----------------------------------------------------------------------
// local (static) support functions follow
//---npt initialize-------------------------------------------------------------
static void _svm_nptinitialize(u32 npt_pdpt_base, u32 npt_pdts_base, u32 npt_pts_base){
	pdpt_t pdpt;
	pdt_t pdt;
	pt_t pt;
	u32 paddr=0, i, j, k, y, z;
	u64 flags;

	printf("\n%s: pdpt=0x%08x, pdts=0x%08x, pts=0x%08x",
	__FUNCTION__, npt_pdpt_base, npt_pdts_base, npt_pts_base);

	pdpt=(pdpt_t)npt_pdpt_base;

	for(i = 0; i < PAE_PTRS_PER_PDPT; i++){
		y = (u32)__hva2spa__((void*)(npt_pdts_base + (i << PAGE_SHIFT_4K)));
		flags = (u64)(_PAGE_PRESENT);
		pdpt[i] = pae_make_pdpe((u64)y, flags);
		pdt=(pdt_t)((u32)npt_pdts_base + (i << PAGE_SHIFT_4K));
			
		for(j=0; j < PAE_PTRS_PER_PDT; j++){
			z=(u32)__hva2spa__((void*)(npt_pts_base + ((i * PAE_PTRS_PER_PDT + j) << (PAGE_SHIFT_4K))));
			flags = (u64)(_PAGE_PRESENT | _PAGE_RW | _PAGE_USER);
			pdt[j] = pae_make_pde((u64)z, flags);
			pt=(pt_t)((u32)npt_pts_base + ((i * PAE_PTRS_PER_PDT + j) << (PAGE_SHIFT_4K)));
			
			for(k=0; k < PAE_PTRS_PER_PT; k++){
				//the EMHF memory region includes the secure loader +
				//the runtime (core + app). this runs from 
				//(rpb->XtVmmRuntimePhysBase - PAGE_SIZE_2M) with a size
				//of (rpb->XtVmmRuntimeSize+PAGE_SIZE_2M)
				//make EMHF physical pages inaccessible
				if( (paddr >= (rpb->XtVmmRuntimePhysBase - PAGE_SIZE_2M)) &&
					(paddr < (rpb->XtVmmRuntimePhysBase + rpb->XtVmmRuntimeSize)) )
					flags = 0;	//not-present
				else
					flags = (u64)(_PAGE_PRESENT | _PAGE_RW | _PAGE_USER);	//present
				pt[k] = pae_make_pte((u64)paddr, flags);
				paddr+= PAGE_SIZE_4K;
			}
		}
	}
	
}

//flush hardware page table mappings (TLB) 
void emhf_memprot_arch_x86svm_flushmappings(VCPU *vcpu){
	((struct vmcb_struct *)(vcpu->vmcb_vaddr_ptr))->tlb_control=TLB_CONTROL_FLUSHALL;	
}

//set protection for a given physical memory address
void emhf_memprot_arch_x86svm_setprot(VCPU *vcpu, u64 gpa, u32 prottype){
	
	
}