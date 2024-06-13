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

//init.c - EMHF early initialization blob functionality
//author: amit vasudevan (amitvasudevan@acm.org)

#ifndef XMHF_BOOTLOADER_COMMON_INIT
#define XMHF_BOOTLOADER_COMMON_INIT

#include <xmhf.h>

#ifndef __ASSEMBLY__

extern uintptr_t hypervisor_image_baseaddress;    //2M aligned highest physical memory address

//size of SL + runtime in bytes
extern size_t sl_rt_size;
extern uint64_t sl_rt_base_spaddr;

extern SL_PARAMETER_BLOCK *slpb;


/// @brief MP config table handling
/// @param uefi_rsdp 
/// @param out_pcpus 
/// @param out_pcpus_numentries 
extern void dealwithMP(void *uefi_rsdp, PCPU* out_pcpus, u32* out_pcpus_numentries);

/// @brief 
/// @param cpu_vendor cpu_vendor = intel or amd
/// @param midtable 
/// @param midtable_numentries 
extern void setupvcpus(u32 cpu_vendor, MIDTAB *midtable, u32 midtable_numentries);

/// @brief Set the <_midtable_numentries> used by internal init functions.
/// @param midtable_numentries 
extern void midtable_set_numentries(u32 midtable_numentries);


extern void wakeupAPs(void);

#endif // __ASSEMBLY__
#endif // XMHF_BOOTLOADER_COMMON_INIT