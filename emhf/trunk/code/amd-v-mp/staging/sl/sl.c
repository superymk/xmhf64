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

//sl.c 
//secure loader implementation
//author: amit vasudevan (amitvasudevan@acm.org)

#include <target.h>


extern u32 slpb_buffer[];


//we get here from slheader.S
void slmain(u32 baseaddr){
	SL_PARAMETER_BLOCK *slpb;
	u32 runtime_physical_base;
	u32 runtime_size_2Maligned;
	
	PXTLPB lpb;
		
	//initialize debugging early on
	#ifdef __DEBUG_SERIAL__		
		init_uart();
	#endif

	#ifdef __DEBUG_VGA__
		vgamem_clrscr();
	#endif
	
	printf("\nSL: at 0x%08x, starting...", baseaddr);
	
	//deal with SL parameter block
	slpb = (SL_PARAMETER_BLOCK *)slpb_buffer;
	printf("\nSL: slpb at = 0x%08x", slpb);
	ASSERT( (u32)slpb == 0x10000 );	//linker relocates sl image starting from 0, so
																  //parameter block must be at offset 0x10000
	ASSERT( slpb->magic == SL_PARAMETER_BLOCK_MAGIC);
	
	printf("\n	hashSL=0x%08x", slpb->hashSL);
	printf("\n	errorHandler=0x%08x", slpb->errorHandler);
	printf("\n	isEarlyInit=0x%08x", slpb->isEarlyInit);
	printf("\n	numE820Entries=%u", slpb->numE820Entries);
	printf("\n	e820map at 0x%08x", &slpb->e820map);
	printf("\n	numCPUEntries=%u", slpb->numCPUEntries);
	printf("\n	pcpus at 0x%08x", &slpb->pcpus);
	printf("\n	runtime size= %u bytes", slpb->runtime_size);
	
	//check for unsuccessful DRT
	//TODO
	
	//get runtime physical base
	runtime_physical_base = baseaddr + PAGE_SIZE_2M;	//base of SL + 2M
	
	//compute 2M aligned runtime size
	runtime_size_2Maligned = PAGE_ALIGN_UP2M(slpb->runtime_size);

	printf("\nSL: runtime at 0x%08x (2M aligned size= %u bytes)", 
			runtime_physical_base, runtime_size_2Maligned);

	//sanitize cache/MTRR/SMRAM (most important is to ensure that MTRRs 
	//do not contain weird mappings)
	//TODO
	
	//setup DMA protection on runtime (secure loader is already DMA protected)
	//TODO
	
	//Measure runtime and sanity check if measurements were fine
	//TODO
	
	
	//setup runtime image for startup
	
		//get a pointer to the runtime header
  	lpb=(PXTLPB)runtime_physical_base;

    //setup paging for runtime and reinitialize pointer to the runtime header
		//runtime_setup_paging(runtime_physical_base, __TARGET_BASE, runtime_size_2Maligned);
		printf("\nSL: setup runtime paging.");	
  	lpb=(PXTLPB)__TARGET_BASE;


	
	
	HALT();
} 