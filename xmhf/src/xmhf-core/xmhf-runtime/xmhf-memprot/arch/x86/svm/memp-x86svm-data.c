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

/**
 * EMHF memory protection component
 * AMD SVM arch. backend implementation data
 * author: amit vasudevan (amitvasudevan@acm.org)
 */

#include <xmhf.h>

#ifdef __UEFI_ALLOCATE_XMHF_RUNTIME_BSS_HIGH__
    u8* g_svm_npt_pdpt_buffers = NULL;
    u8* g_svm_npt_pdts_buffers = NULL;
    u8* g_svm_npt_pts_buffers = NULL;

#else

    //SVM NPT PDPT buffers
    //memprot
    u8 g_svm_npt_pdpt_buffers[PAGE_SIZE_4K * XMHF_RICH_GUEST_NPT_NUM] __attribute__((aligned(PAGE_SIZE_4K)));

    //SVM NPT PDT buffers
    //memprot
    u8 g_svm_npt_pdts_buffers[PAE_PTRS_PER_PDPT * PAGE_SIZE_4K * XMHF_RICH_GUEST_NPT_NUM] __attribute__((aligned(PAGE_SIZE_4K)));

    //SVM NPT PT buffers
    //memprot
    u8 g_svm_npt_pts_buffers[PAE_PTRS_PER_PDPT * PAE_PTRS_PER_PDT * PAGE_SIZE_4K * XMHF_RICH_GUEST_NPT_NUM] __attribute__((aligned(PAGE_SIZE_4K)));
#endif // __UEFI_ALLOCATE_XMHF_RUNTIME_BSS_HIGH__



