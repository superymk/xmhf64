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

// peh-x86-safemsr.c
// Safely read / write MSRs by catching #GP exceptions
// author: Eric Li (xiaoyili@andrew.cmu.edu)
#include <xmhf.h>

/*
 * Perform RDMSR instruction.
 * If successful, return 0. If RDMSR causes #GP, return 1.
 * Implementation similar to Linux's native_read_msr_safe().
 */
u32 rdmsr_safe(u32 index, u64 *value) {
    u32 result;
    u32 eax, edx;
    asm volatile ("1:\r\n"
                  "rdmsr\r\n"
                  "xor %%ebx, %%ebx\r\n"
                  "jmp 3f\r\n"
                  "2:\r\n"
                  "movl $1, %%ebx\r\n"
                  "jmp 3f\r\n"
                  ".section .xcph_table\r\n"
#ifdef __AMD64__
                  ".quad 0xd\r\n"
                  ".quad 1b\r\n"
                  ".quad 2b\r\n"
#elif defined(__I386__)
                  ".long 0xd\r\n"
                  ".long 1b\r\n"
                  ".long 2b\r\n"
#else /* !defined(__I386__) && !defined(__AMD64__) */
    #error "Unsupported Arch"
#endif /* !defined(__I386__) && !defined(__AMD64__) */
                  ".previous\r\n"
                  "3:\r\n"
                  : "=a"(eax), "=d"(edx), "=b"(result)
                  : "c" (index));
	if (result == 0) {
		*value = ((u64) edx << 32) | eax;
	}
    return result;
}

/*
 * Perform WRMSR instruction.
 * If successful, return 0. If WRMSR causes #GP, return 1.
 * Implementation similar to Linux's native_write_msr_safe().
 */
u32 wrmsr_safe(u32 index, u64 value) {
    u32 result;
    u32 eax = (u32) value, edx = (value >> 32);
    asm volatile ("1:\r\n"
                  "wrmsr\r\n"
                  "xor %%ebx, %%ebx\r\n"
                  "jmp 3f\r\n"
                  "2:\r\n"
                  "movl $1, %%ebx\r\n"
                  "jmp 3f\r\n"
                  ".section .xcph_table\r\n"
#ifdef __AMD64__
                  ".quad 0xd\r\n"
                  ".quad 1b\r\n"
                  ".quad 2b\r\n"
#elif defined(__I386__)
                  ".long 0xd\r\n"
                  ".long 1b\r\n"
                  ".long 2b\r\n"
#else /* !defined(__I386__) && !defined(__AMD64__) */
    #error "Unsupported Arch"
#endif /* !defined(__I386__) && !defined(__AMD64__) */
                  ".previous\r\n"
                  "3:\r\n"
                  : "=b"(result)
                  : "c" (index), "a"(eax), "d"(edx));
    return result;
}
