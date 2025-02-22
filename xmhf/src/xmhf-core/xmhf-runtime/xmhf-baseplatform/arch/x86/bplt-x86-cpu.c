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

/*
 * XMHF base platform component interface, x86 common backend
 * general CPU functions
 * author: amit vasudevan (amitvasudevan@acm.org)
 */

#include <xmhf.h>

static inline void clflush_ins(volatile void *p)
{
	// asm volatile("clflush %0" : "+m" (*(volatile char *)__p));
	asm volatile ("clflush (%0)" :: "r"(p));
}

//returns true if CPU has support for XSAVE/XRSTOR
bool xmhf_baseplatform_arch_x86_cpuhasxsavefeature(void){
	u32 eax, ebx, ecx, edx;

	//bit 26 of ECX is 1 in CPUID function 0x00000001 if
	//XSAVE/XRSTOR feature is available

	cpuid(0x00000001, &eax, &ebx, &ecx, &edx);

	if((ecx & (1UL << 26)))
		return true;
	else
		return false;

}

//! @brief Sleep the current core for <us> micro-second.
void xmhf_cpu_delay_us_rdtsc(uint64_t us)
{
    uint64_t cycles = CPU_CYCLES_PER_MICRO_SEC * us;
    uint64_t start = rdtsc64();
    
    while ( rdtsc64()-start < cycles ) ;
}

void xmhf_cpu_flush_cache_range(void *vaddr, unsigned int size)
{
	const unsigned long clflush_size = ((cpuid_ebx(1) >> 8) & 0xff) << 3;
	void *p = (void *)((unsigned long)vaddr & ~(clflush_size - 1));
	void *vend = vaddr + size;

	if (p >= vend)
		return;

	for (; p < vend; p += clflush_size)
		clflush_ins(p);
}

#define UDELAY_PER_ROUND    (10000)
void xmhf_cpu_delay_us(uint64_t usecs)
{
    uint64_t round = usecs / UDELAY_PER_ROUND;
    uint32_t remain = usecs % UDELAY_PER_ROUND;
    uint64_t i = 0;

    // <xmhf_baseplatform_arch_x86_udelay> must be <= 65000us, so we use a loop for longer sleep time.
    xmhf_baseplatform_arch_x86_udelay(remain);

    for(i = 0; i < round; i++)
    {
        xmhf_baseplatform_arch_x86_udelay(UDELAY_PER_ROUND);
    }
}