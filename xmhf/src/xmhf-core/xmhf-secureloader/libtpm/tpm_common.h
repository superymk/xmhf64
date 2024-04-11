/*
 * -------------------------------------------------------------------------------------
 * Carnegie Mellon University
 * Copyright (C) 2023 - 2023 Carnegie Mellon University. All Rights Reserved.
 * 
 * This software is the proprietary information of Carnegie Mellon University.
 * Use is subject to license terms.
 * 
 * Any reproduction, modification, distribution, or disclosure of this software, or any part of it, without the express
 * written consent of Carnegie Mellon University. is strictly prohibited.
 * -------------------------------------------------------------------------------------
 * 
 * Authors: Miao Yu
 *          Virgil Gligor
 */


#ifndef _TPM_COMMON_H
#define _HASH_FUNCS_H

// XMHF-SL only: The TPM functions used by XMHF-SL need a small input and output buffer only.
#define XMHF_SL_TPM_MAX_COMMAND_SIZE   (96)
#define XMHF_SL_TPM_MAX_RESPONSE_SIZE  (96)

#ifndef __ASSEMBLY__

extern u8 cmd_buf[XMHF_SL_TPM_MAX_COMMAND_SIZE];
extern u8 rsp_buf[XMHF_SL_TPM_MAX_RESPONSE_SIZE];

#endif // __ASSEMBLY__
#endif // _HASH_FUNCS_H