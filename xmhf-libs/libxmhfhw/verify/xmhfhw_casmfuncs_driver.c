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
 * libxmhfhw CASM functions verification driver
 * author: amit vasudevan (amitvasudevan@acm.org)
*/


#include <xmhf.h>
#include <xmhf-hwm.h>
#include <xmhfgeec.h>
#include <xmhf-debug.h>

u32 cpuid = 0;	//BSP cpu

//////
// frama-c non-determinism functions
//////

u32 Frama_C_entropy_source;

//@ assigns Frama_C_entropy_source \from Frama_C_entropy_source;
void Frama_C_update_entropy(void);

u32 framac_nondetu32(void){
  Frama_C_update_entropy();
  return (u32)Frama_C_entropy_source;
}

u32 framac_nondetu32interval(u32 min, u32 max)
{
  u32 r,aux;
  Frama_C_update_entropy();
  aux = Frama_C_entropy_source;
  if ((aux>=min) && (aux <=max))
    r = aux;
  else
    r = min;
  return r;
}


//////
u32 saved_cpu_gprs_ebx=0;
u32 saved_cpu_gprs_esi=0;
u32 saved_cpu_gprs_edi=0;

void cabi_establish(void){
	xmhfhwm_cpu_gprs_ebx = 5UL;
	xmhfhwm_cpu_gprs_esi = 6UL;
	xmhfhwm_cpu_gprs_edi = 7UL;
	saved_cpu_gprs_ebx = xmhfhwm_cpu_gprs_ebx;
	saved_cpu_gprs_esi = xmhfhwm_cpu_gprs_esi;
	saved_cpu_gprs_edi = xmhfhwm_cpu_gprs_edi;
}

void cabi_check(void){
	//@ assert saved_cpu_gprs_ebx == xmhfhwm_cpu_gprs_ebx;
	//@ assert saved_cpu_gprs_esi == xmhfhwm_cpu_gprs_esi;
	//@ assert saved_cpu_gprs_edi == xmhfhwm_cpu_gprs_edi;
}


void drv_bsrl(void){
	uint32_t param1=framac_nondetu32();
	uint32_t result;
	cabi_establish();
        result = CASM_FUNCCALL(bsrl, param1);
	cabi_check();
}

void drv_cpuid(void){
	u32 eax = framac_nondetu32();
	u32 ebx = framac_nondetu32();
	u32 ecx = framac_nondetu32();
	u32 edx = framac_nondetu32();
	u32 op = framac_nondetu32();
	cabi_establish();
	CASM_FUNCCALL(xmhfhw_cpu_cpuid, op, &eax, &ebx, &ecx, &edx);
	cabi_check();
}

void drv_disableintr(void){
	cabi_establish();
	CASM_FUNCCALL(xmhfhw_cpu_disable_intr, CASM_NOPARAM);
	cabi_check();
}

void drv_enableintr(void){
	cabi_establish();
	CASM_FUNCCALL(enable_intr, CASM_NOPARAM);
	cabi_check();
}

void drv_getgdtbase(void){
	u64 result;
	cabi_establish();
	result = CASM_FUNCCALL(xmhf_baseplatform_arch_x86_getgdtbase, CASM_NOPARAM);
	cabi_check();
}

void drv_getidtbase(void){
	u64 result;
	cabi_establish();
	result = CASM_FUNCCALL(xmhf_baseplatform_arch_x86_getidtbase, CASM_NOPARAM);
	cabi_check();
}

void drv_getsec(void){
	u32 eax=0, ebx=0, ecx=0, edx=0;
	cabi_establish();
	CASM_FUNCCALL(xmhfhw_cpu_getsec, &eax, &ebx, &ecx, &edx);
	cabi_check();
}

void drv_gettssbase(void){
	u64 result;
	cabi_establish();
	result = CASM_FUNCCALL(xmhf_baseplatform_arch_x86_gettssbase, CASM_NOPARAM);
	cabi_check();
}





void main(void){
	u32 check_esp, check_eip = CASM_RET_EIP;

	//populate hardware model stack and program counter
	xmhfhwm_cpu_gprs_esp = _slab_tos[cpuid];
	xmhfhwm_cpu_gprs_eip = check_eip;
	check_esp = xmhfhwm_cpu_gprs_esp; // pointing to top-of-stack

	//execute harness: TODO
	//drv_bsrl();
	//drv_cpuid();
	//drv_disableintr();
	//drv_enableintr();
	//drv_getgdtbase();
	//drv_getidtbase();
	//drv_getsec();
	drv_gettssbase();

	//@assert xmhfhwm_cpu_gprs_esp == check_esp;
	//@assert xmhfhwm_cpu_gprs_eip == check_eip;
}


