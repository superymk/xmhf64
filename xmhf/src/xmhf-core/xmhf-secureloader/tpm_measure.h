/*
 * @XMHF_LICENSE_HEADER_START@
 *
 * eXtensible, Modular Hypervisor Framework (XMHF)
 * Copyright (c) 2023 - 2024 Miao Yu
 * Copyright (c) 2023 - 2024 Virgil Gligor
 * All Rights Reserved.
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
 * Neither the name of the copyright holder nor the names of
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

#ifndef _SL_TPM_MEASURE_H
#define _SL_TPM_MEASURE_H

#include <xmhf.h>

#define TPM_PCR_BOOT_STATE   (7)
#define TPM_PCR_DRTM_IMAGE  (17)

#ifndef __ASSEMBLY__

/// @brief Measure the xmhf-runtime.
/// [NOTE] This function must be called before <xmhf_sl_handle_rt_rela_dyn>, which modifies xmhf-runtime image for
/// relocation. 
/// [NOTE] xmhf-sl assumes that xmhf-runtime's code and rodata sections must be placed before its data section.
/// @param rpb 
/// @param xmhf_rt_data_end The end of the xmhf-runtime data section. 
/// @return 
extern int xmhf_sl_tpm_measure_runtime(RPB *rpb, hva_t xmhf_rt_data_end);

#endif // __ASSEMBLY__
#endif // _SL_TPM_MEASURE_H