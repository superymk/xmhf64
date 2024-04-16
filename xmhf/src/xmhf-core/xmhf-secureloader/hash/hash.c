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

/* $OpenBSD: sk-usbhid.c,v 1.46 2023/03/28 06:12:38 dtucker Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl
 * Copyright (c) 2020 Pedro Martelletto
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "hash.h"

int sha2_256_mem_to_20bytes(const void *m, size_t mlen, uint8_t *d)
{
    SHA2_CTX ctx;
    uint8_t d_sha256[SHA256_DIGEST_LENGTH];

    if(!m || !mlen || !d)
        return -1;

    SHA256Init(&ctx);
	SHA256Update(&ctx, (const uint8_t *)m, mlen);
	SHA256Final(d_sha256, &ctx);

    memcpy(d, d_sha256, SHA1_DIGEST_LENGTH);

    return 0;
}

// int sha1_mem(const void *m, size_t mlen, uint8_t *d)
// {
//     SHA1_CTX ctx;

//     if(!m || !mlen || !d)
//         return -1;

//     SHA1Init(&ctx);
// 	SHA1Update(&ctx, (const uint8_t *)m, mlen);
// 	SHA1Final(d, &ctx);

//     return 0;
// }

int sha2_256_mem(const void *m, size_t mlen, uint8_t *d)
{
    SHA2_CTX ctx;

    if(!m || !mlen || !d)
        return -1;

    SHA256Init(&ctx);
	SHA256Update(&ctx, (const uint8_t *)m, mlen);
	SHA256Final(d, &ctx);

    return 0;
}