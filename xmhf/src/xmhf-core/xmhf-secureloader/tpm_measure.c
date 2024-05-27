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

#include "tpm_measure.h"
#include "./hash/hash.h"

/// @brief Return true iff xmhf-sl can use the physical TPM device (either TPM 1.2 or TPM 2.0).
/// @param out_tpm 
/// @param out_tpm_fp 
/// @return 
static bool _is_tpm_present(struct tpm_if **out_tpm, struct tpm_if_fp **out_tpm_fp)
{
    struct tpm_if *tpm = get_tpm();
    struct tpm_if_fp *tpm_fp = NULL;

// [TODO][Github-XMHF64 Issue 13] A QEMU issue? If XMHF accesses SW TPM of QEMU with tpm20.c, then QEMU reports the 
// error "Buffer Too Small" when loading the OS bootloader
#if defined(__DEBUG_QEMU__) && defined(__UEFI__) && !defined(__FORCE_TPM_1_2__)
    {
        printf("xmhf-sl: No support of SW TPM2.0 in QEMU!\n");
        return false;
    }
#endif // defined(__DEBUG_QEMU__) && defined(__UEFI__)

    if(!tpm)
    {
        printf("xmhf-sl: Failed to get <tpm>!\n");
        return false;
    }

    if(!tpm_detect())
    {
        printf("xmhf-sl: Failed to get TPM version!\n");
        return false;
    }

    tpm_fp = (struct tpm_if_fp *)get_tpm_fp();
    if(!tpm_fp)
    {
        printf("xmhf-sl: Failed to get <tpm_fp>!\n");
        return false;
    }

    // Check TPM versions
    if((tpm->major != TPM12_VER_MAJOR) && (tpm->major != TPM20_VER_MAJOR))
    {
        printf("xmhf-sl: Unknown TPM version!\n");
        return false;
    }

    // On success
    *out_tpm = tpm;
    *out_tpm_fp = tpm_fp;
    return true;
}

static hva_t _xmhf_runtime_get_base_hvaddr(RPB *rpb)
{
    return rpb->XtVmmRuntimeVirtBase;
}

int xmhf_sl_tpm_measure_runtime(RPB *rpb, hva_t xmhf_rt_data_end)
{
    struct tpm_if *tpm = NULL;
    struct tpm_if_fp *tpm_fp = NULL;
    bool found_tpm = false;

    found_tpm = _is_tpm_present(&tpm, &tpm_fp);
    if(!found_tpm)
    {
        // XMHF cannot use TPM. Warn it loud.
        printf("**********************************************************************************************\n");
        printf("[INSECURITY] XMHF CANNOT USE TPM!\n");
        printf("**********************************************************************************************\n");
        
        return 1;
    }

    // Measure xmhf-runtime into TPM PCRs
    // [NOTE] Even with DRTM enabled, xmhf-bootloader must measure xmhf-runtime into PCR7 to maintain the security of 
    // red OS. Otherwise, remote attackers can compromise xmhf-runtime to steal Bitlocker "volume master key" and reboot
    // immediately. So the attacker can get the secret without getting exposed in PCR7 (or anywhere in PCR0-15). 
    {
        union sha_digest digest = {0};
        int result = 0;
        hva_t xmhf_rt_base = _xmhf_runtime_get_base_hvaddr(rpb);
        size_t xmhf_rt_code_data_size = xmhf_rt_data_end - xmhf_rt_base;

        // Measure xmhf-runtime
        printf("SL: Measure xmhf-runtime start. XMHF-runtime code and data size:0x%lX\n", xmhf_rt_code_data_size);
        if(tpm->major == TPM12_VER_MAJOR)
        {
            result = sha2_256_mem_to_20bytes((void*)xmhf_rt_base, xmhf_rt_code_data_size, digest.sha1_digest);
            if(result)
            {
                printf("SL: Measure xmhf-runtime with SHA1 error!\n");
                return 1;
            }
        }
        else if(tpm->major == TPM20_VER_MAJOR)
        {
            result = sha2_256_mem((void*)xmhf_rt_base, xmhf_rt_code_data_size, digest.sha2_256_digest);
            if(result)
            {
                printf("SL: Measure xmhf-runtime with SHA256 error!\n");
                return 1;
            }
        }
        // No need to check invalid <tpm->major> again, because we have checked it.

        //// Extend into PCRs
        if(tpm->major == TPM12_VER_MAJOR)
        {
            hash_list_t hl;

            hl.count = 1;
            hl.entries[0].alg = TB_HALG_SHA1;
            memcpy(&hl.entries[0].hash.sha1, digest.sha1_digest, SHA1_DIGEST_LENGTH);

            result = tpm_fp->pcr_extend(tpm, 0, TPM_PCR_BOOT_STATE, &hl);
            if(!result)
            {
                printf("SL (TPM1.2): Extend to PCR7 error!\n");
                return 1;
            }

#if defined (__DRT__)
            result = tpm_fp->pcr_extend(tpm, 2, TPM_PCR_DRTM_IMAGE, &hl);
            if(!result)
            {
                printf("SL (TPM1.2): Extend to PCR17 error!\n");
                return 1;
            }
#endif	//__DRT__
        }
        else if(tpm->major == TPM20_VER_MAJOR)
        {
            hash_list_t hl;

            hl.count = 1;
            hl.entries[0].alg = TB_HALG_SHA256;
            memcpy(&hl.entries[0].hash.sha256, digest.sha2_256_digest, SHA256_DIGEST_LENGTH);

            result = tpm_fp->pcr_extend(tpm, 0, TPM_PCR_BOOT_STATE, &hl);
            if(!result)
            {
                printf("SL (TPM2): Extend to PCR7 error!\n");
                return 1;
            }

#if defined (__DRT__)
            result = tpm_fp->pcr_extend(tpm, 2, TPM_PCR_DRTM_IMAGE, &hl);
            if(!result)
            {
                printf("SL (TPM2): Extend to PCR17 error!\n");
                return 1;
            }
#endif	//__DRT__
        }
        // No need to check invalid <tpm->major> again, because we have checked it.

        printf("SL: Extended xmhf-runtime measurement\n");
    }

    // On success
    return 0;
}