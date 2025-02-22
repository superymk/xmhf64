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

// EMHF x86 arch. specific configurable definitions
// author: amit vasudevan (amitvasudevan@acm.org)
// author: Eric Li
// author: Miao Yu

// This file must be modified first to support hardware configuration

#ifndef __XMHF_CONFIG_H__
#define __XMHF_CONFIG_H__

// maximum supported physical address, currently 16GB
// Note: This value must be larger than 4GB
#ifdef __I386__
    // Note: 32-bit XMHF (non-PAE) always assumes the maximum physical memory size == 4GB.
	#define MAX_PHYS_ADDR					ADDR_4GB
#elif defined(__AMD64__)
	#define MAX_PHYS_ADDR                   (AMD64_MAX_PHYS_ADDR)
#else
    #error "Unsupported Arch"
#endif // __I386__


/********* Configs of entire XMHF *********/
// max. cores/vcpus we support currently
#define MAX_MIDTAB_ENTRIES  			(256)
#define MAX_PCPU_ENTRIES  				(MAX_MIDTAB_ENTRIES)
#define MAX_VCPU_ENTRIES    			(MAX_PCPU_ENTRIES)



/********* Configs of xmhf-secureloader *********/
/// @brief Size of xmhf-sl code, rodata, and data sections that need to be measured. When DRTM is enabled, DRTM should
/// measure these sections and execute the code.
#define SL_LOW_CODE_DATA_SECTION_SIZE   (KB(128))

#ifndef __ASSEMBLY__

#endif // __ASSEMBLY__
#endif // __XMHF_CONFIG_H__
