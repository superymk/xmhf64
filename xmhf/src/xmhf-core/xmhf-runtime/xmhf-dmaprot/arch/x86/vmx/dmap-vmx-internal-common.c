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

// EMHF DMA protection component implementation for x86 VMX
// author: amit vasudevan (amitvasudevan@acm.org)

#include <xmhf.h>
#include "dmap-vmx-internal.h"

struct dmap_vmx_cap g_vtd_cap_sagaw_mgaw_nd;

//------------------------------------------------------------------------------
// vt-d register access function
void _vtd_reg(VTD_DRHD *dmardevice, u32 access, u32 reg, void *value)
{
    u32 regtype = VTD_REG_32BITS, regaddr = 0;

    // obtain register type and base address
    switch (reg)
    {
    // 32-bit registers
    case VTD_VER_REG_OFF:
    case VTD_GCMD_REG_OFF:
    case VTD_GSTS_REG_OFF:
    case VTD_FSTS_REG_OFF:
    case VTD_FECTL_REG_OFF:
    case VTD_PMEN_REG_OFF:
        regtype = VTD_REG_32BITS;
        regaddr = dmardevice->regbaseaddr + reg;
        break;

    // 64-bit registers
    case VTD_CAP_REG_OFF:
    case VTD_ECAP_REG_OFF:
    case VTD_RTADDR_REG_OFF:
    case VTD_CCMD_REG_OFF:
        regtype = VTD_REG_64BITS;
        regaddr = dmardevice->regbaseaddr + reg;
        break;

    case VTD_IOTLB_REG_OFF:
    {
        VTD_ECAP_REG t_vtd_ecap_reg;
        regtype = VTD_REG_64BITS;
#ifndef __XMHF_VERIFICATION__
        _vtd_reg(dmardevice, VTD_REG_READ, VTD_ECAP_REG_OFF, (void *)&t_vtd_ecap_reg.value);
#endif
        regaddr = dmardevice->regbaseaddr + (t_vtd_ecap_reg.bits.iro * 16) + 0x8;
        break;
    }

    case VTD_IVA_REG_OFF:
    {
        VTD_ECAP_REG t_vtd_ecap_reg;
        regtype = VTD_REG_64BITS;
#ifndef __XMHF_VERIFICATION__
        _vtd_reg(dmardevice, VTD_REG_READ, VTD_ECAP_REG_OFF, (void *)&t_vtd_ecap_reg.value);
#endif
        regaddr = dmardevice->regbaseaddr + (t_vtd_ecap_reg.bits.iro * 16);
        break;
    }

    default:
        printf("%s: Halt, Unsupported register=%08x\n", __FUNCTION__, reg);
        HALT();
        break;
    }

    // perform the actual read or write request
    switch (regtype)
    {
    case VTD_REG_32BITS:
    { // 32-bit r/w
        if (access == VTD_REG_READ)
            *((u32 *)value) = xmhf_baseplatform_arch_flat_readu32(regaddr);
        else
            xmhf_baseplatform_arch_flat_writeu32(regaddr, *((u32 *)value));

        break;
    }

    case VTD_REG_64BITS:
    { // 64-bit r/w
        if (access == VTD_REG_READ)
            *((u64 *)value) = xmhf_baseplatform_arch_flat_readu64(regaddr);
        else
            xmhf_baseplatform_arch_flat_writeu64(regaddr, *((u64 *)value));

        break;
    }

    default:
        printf("%s: Halt, Unsupported access width=%08x\n", __FUNCTION__, regtype);
        HALT();
    }

    return;
}

// Return true if verification of VT-d capabilities succeed.
// Success means:
// (0) <out_cap> must be valid
// (1) Same AGAW, MGAW, and ND across VT-d units
// (2) supported MGAW to ensure our host address width is supported (32-bits)
// (3) AGAW must support 39-bits or 48-bits
// (4) Number of domains must not be unsupported
bool _vtd_verify_cap(VTD_DRHD *vtd_drhd, u32 vtd_num_drhd, struct dmap_vmx_cap *out_cap)
{
#define INVALID_SAGAW_VAL 0xFFFFFFFF
#define INVALID_MGAW_VAL 0xFFFFFFFF
#define INVALID_NUM_DOMAINS 0xFFFFFFFF

    VTD_CAP_REG cap;
    u32 i = 0;
    u32 last_sagaw = INVALID_SAGAW_VAL;
    u32 last_mgaw = INVALID_MGAW_VAL;
    u32 last_nd = INVALID_NUM_DOMAINS;

    // Sanity checks
    if (!out_cap)
        return false;

    if (!vtd_drhd)
        return false;

    if (!vtd_num_drhd || vtd_num_drhd >= VTD_MAX_DRHD) // Support maximum of VTD_MAX_DRHD VT-d units
        return false;

    for (i = 0; i < vtd_num_drhd; i++)
    {
        VTD_DRHD *drhd = &vtd_drhd[i];
        printf("%s: verifying DRHD unit %u...\n", __FUNCTION__, i);

        // read CAP register
        _vtd_reg(drhd, VTD_REG_READ, VTD_CAP_REG_OFF, (void *)&cap.value);

        // Check: Same AGAW, MGAW and ND across VT-d units
        if (cap.bits.sagaw != last_sagaw)
        {
            if (last_sagaw == INVALID_SAGAW_VAL)
            {
                // This must the first VT-d unit
                last_sagaw = cap.bits.sagaw;
            }
            else
            {
                // The current VT-d unit has different capabilities with some other units
                printf("  [VT-d] Check error! Different SAGAW capability found on VT-d unix %u. last sagaw:0x%08X, current sagaw:0x%08X\n",
                       i, last_sagaw, cap.bits.sagaw);
                return false;
            }
        }

        if (cap.bits.mgaw != last_mgaw)
        {
            if (last_mgaw == INVALID_MGAW_VAL)
            {
                // This must the first VT-d unit
                last_mgaw = cap.bits.mgaw;
            }
            else
            {
                // The current VT-d unit has different capabilities with some other units
                printf("  [VT-d] Check error! Different MGAW capability found on VT-d unix %u. last mgaw:0x%08X, current mgaw:0x%08X\n",
                       i, last_mgaw, cap.bits.mgaw);
                return false;
            }
        }

        if (cap.bits.nd != last_nd)
        {
            if (last_nd == INVALID_NUM_DOMAINS)
            {
                // This must the first VT-d unit
                last_nd = cap.bits.nd;
            }
            else
            {
                // The current VT-d unit has different capabilities with some other units
                printf("  [VT-d] Check error! Different ND capability found on VT-d unix %u. last nd:0x%08X, current nd:0x%08X\n",
                       i, last_nd, cap.bits.nd);
                return false;
            }
        }

        // Check: supported MGAW to ensure our host address width is supported (32-bits)
        if (cap.bits.mgaw < 31)
        {
            printf("  [VT-d] Check error! GAW < 31 (%u) unsupported.\n", cap.bits.mgaw);
            return false;
        }

        // Check: AGAW must support 39-bits or 48-bits
        if (!(cap.bits.sagaw & 0x2 || cap.bits.sagaw & 0x4))
        {
            printf("	[VT-d] Check error! AGAW does not support 3-level or 4-level page-table. See sagaw capabilities:0x%08X. Halting!\n", cap.bits.sagaw);
            return false;
        }
        else
        {
            out_cap->sagaw = cap.bits.sagaw;
        }

        // Check: Number of domains must not be unsupported
        if (cap.bits.nd == 0x7)
        {
            printf("  [VT-d] Check error! ND == 0x7 unsupported on VT-d unix %u.\n", i);
            return false;
        }
        else
        {
            out_cap->nd = cap.bits.nd;
        }
    }

    printf("Verify all Vt-d units success\n");

    return true;
}

//------------------------------------------------------------------------------
// According to Intel Virtualization Technology for Directed I/O specification, Section 11.4.4.1 Global Command Register.
#define VTD_GSTS_MASK_FOR_GCMD  (0x96FFFFFF)

//! @brief Modify an individual bit of Global Command Register.
void _vtd_drhd_issue_gcmd(VTD_DRHD *drhd, u32 offset, u32 val)
{
    VTD_GCMD_REG gcmd;
    VTD_GSTS_REG gsts;

    // Check: <offset> must be in [0, 31]
    if(offset >= 32)
        return;

    // According to Intel Virtualization Technology for Directed I/O specification, Section 11.4.4.1 Global Command Register.
    _vtd_reg(drhd, VTD_REG_READ, VTD_GSTS_REG_OFF, (void *)&gsts.value);
    gsts.value &= VTD_GSTS_MASK_FOR_GCMD;

    if(val)
        gcmd.value = gsts.value | (1UL << offset);
    else
        gcmd.value = gsts.value & ~(1UL << offset);
    
    _vtd_reg(drhd, VTD_REG_WRITE, VTD_GCMD_REG_OFF, (void *)&gcmd.value);
}

// Issue Write Buffer Flusing (WBF) if the IOMMU requires it.
void _vtd_drhd_issue_wbf(VTD_DRHD *drhd)
{
    VTD_GSTS_REG gsts;

    // sanity check
    HALT_ON_ERRORCOND(drhd != NULL);

    if (!vtd_cap_require_wbf(drhd))
        // Not need to issue Write Buffer Flusing (WBF)
        return;

    _vtd_drhd_issue_gcmd(drhd, VTD_GCMD_BIT_WBF, 1);
    IOMMU_WAIT_OP(drhd, VTD_GSTS_REG_OFF, !gsts.bits.wbfs, (void *)&gsts.value, "	Cannot perform WBF. Halting!");
}
