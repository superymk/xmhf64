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


#ifndef _HASH_FUNCS_H
#define _HASH_FUNCS_H

#include <xmhf.h>

#include "hash_defines.h"
#include "sha1.h"
#include "sha2.h"

#ifndef __ASSEMBLY__

union sha_digest
{
    uint8_t sha1_digest[SHA1_DIGEST_LENGTH];
    uint8_t sha2_256_digest[SHA256_DIGEST_LENGTH];
};

// extern int sha1_mem(const void *m, size_t mlen, uint8_t *d);

/// @brief Save code space in xmhf-SL by replacing SHA1 with SHA256 truncated to 20 bytes.
/// @param m 
/// @param mlen 
/// @param d 
/// @return 
extern int sha2_256_mem_to_20bytes(const void *m, size_t mlen, uint8_t *d);
extern int sha2_256_mem(const void *m, size_t mlen, uint8_t *d);

#endif // __ASSEMBLY__
#endif // _HASH_FUNCS_H