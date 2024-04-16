/*
 * Copyright (c) 1999-2003 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _DEFINES_H
#define _DEFINES_H

#include <xmhf.h>

#ifndef __ASSEMBLY__

#define DEF_WEAK(x) 
#define explicit_bzero(buf, len) memset(buf, 0, len)

#if defined (__I386__) || defined(__AMD64__)
    #define BYTE_ORDER LITTLE_ENDIAN
#else // !defined(__I386__) && !defined(__AMD64__)
    #define BYTE_ORDER BIG_ENDIAN
#endif // defined(__I386__) && !defined(__AMD64__)

#if !defined(__GNUC__) || (__GNUC__ < 2)
# define __attribute__(x)
#endif // !defined(__GNUC__) || (__GNUC__ < 2)

#if !defined(HAVE_ATTRIBUTE__SENTINEL__) && !defined(__sentinel__)
# define __sentinel__
#endif

#if !defined(HAVE_ATTRIBUTE__BOUNDED__) && !defined(__bounded__)
# define __bounded__(x, y, z)
#endif

#endif // __ASSEMBLY__
#endif // _DEFINES_H