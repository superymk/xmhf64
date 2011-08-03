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

#ifndef _PAL_UTPM_H_
#define _PAL_UTPM_H_

/* PAL uTPM operations */
uint32_t hc_utpm_seal(VCPU * vcpu, uint32_t input_addr, uint32_t input_len, uint32_t tpmPcrInfo_addr, uint32_t output_addr, uint32_t output_len_addr);
uint32_t hc_utpm_unseal(VCPU * vcpu, uint32_t input_addr, uint32_t input_len, uint32_t output_addr, uint32_t output_len_addr, uint32_t digestAtCreation_addr);
u32 hc_utpm_seal_deprecated(VCPU * vcpu, u32 input_addr, u32 input_len, u32 pcrAtRelease_addr, u32 output_addr, u32 output_len_addr);
u32 hc_utpm_unseal_deprecated(VCPU * vcpu, u32 input_addr, u32 input_len, u32 output_addr, u32 output_len_addr);
u32 hc_utpm_quote_deprecated(VCPU * vcpu, u32 nonce_addr, u32 tpmsel_addr, u32 out_addr, u32 out_len_addr);
u32 hc_utpm_quote(VCPU * vcpu, u32 nonce_addr, u32 tpmsel_addr, u32 out_addr, u32 out_len_addr, u32 pcrComp_addr, u32 pcrCompLen_addr);
uint32_t hc_utpm_utpm_id_getpub(VCPU * vcpu, uint32_t gvaddr);
u32 hc_utpm_pcrread(VCPU * vcpu, u32 gvaddr, u32 num);
u32 hc_utpm_pcrextend(VCPU * vcpu, u32 idx, u32 meas_gvaddr);
u32 hc_utpm_rand(VCPU * vcpu, u32 buffer_addr, u32 numbytes_addr);

#endif /* _PAL_UTPM_H_ */


