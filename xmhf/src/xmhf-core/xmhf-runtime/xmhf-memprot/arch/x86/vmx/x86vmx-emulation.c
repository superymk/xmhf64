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

// peh-x86vmx-emulation.c
// Emulate selected x86 instruction
// author: Eric Li (xiaoyili@andrew.cmu.edu)
#include <xmhf.h>

#define INST_LEN_MAX	15
#define BIT_SIZE_64		8
#define BIT_SIZE_32		4
#define BIT_SIZE_16		2
#define BIT_SIZE_8		1

/* Environment used to access memory */
typedef struct mem_access_env_t {
	void *hvaddr;
	gva_t gaddr;
	cpu_segment_t seg;
	size_t size;
	hpt_prot_t mode;
	hptw_cpl_t cpl;
} mem_access_env_t;

static void _print_instruction(unsigned char* inst, uint32_t inst_len);

// #define PREFIX_INFO_INITIALIZER 
// 	{ false, false, false, CPU_SEG_UNKNOWN, false, false, { .raw=0 } }



// /*
//  * Handle access of special memory.
//  * Interface similar to hptw_checked_access_va.
//  */
// static void access_special_memory(VCPU * vcpu, void *hva,
// 								  hpt_prot_t access_type, hptw_cpl_t cpl,
// 								  gpa_t gpa, size_t requested_sz,
// 								  size_t *avail_sz)
// {
// 	if ((gpa & PAGE_MASK_4K) == g_vmx_lapic_base) {
// 		HALT_ON_ERRORCOND(requested_sz == 4);
// 		HALT_ON_ERRORCOND(gpa % 4 == 0);
// 		HALT_ON_ERRORCOND(cpl == 0);
// 		*avail_sz = 4;
// 		if ((gpa & ADDR64_PAGE_OFFSET_4K) == LAPIC_ICR_LOW &&
// 			(access_type & HPT_PROT_WRITE_MASK)) {
// 			xmhf_smpguest_arch_x86vmx_eventhandler_icrlowwrite(vcpu,
// 															   *(u32 *)hva);
// 		} else {
// 			if (access_type & HPT_PROT_WRITE_MASK) {
// 				*(u32 *)(uintptr_t)gpa = *(u32 *)hva;
// 			} else {
// 				*(u32 *)hva = *(u32 *)(uintptr_t)gpa;
// 			}
// 		}
// 	} else {
// 		HALT_ON_ERRORCOND(0);
// 	}
// }

static hva_t eval_guest_memory_gvaddr(guestmem_hptw_ctx_pair_t * ctx_pair, mem_access_env_t * env, uintptr_t guest_mem_linear_addr)
{
	VCPU *vcpu = ctx_pair->vcpu;

	return guestmem_desegment(vcpu, env->seg, guest_mem_linear_addr, env->size,
								  env->mode, env->cpl);
}	

/* Access memory from guest logical address. */
static int access_memory_gv(guestmem_hptw_ctx_pair_t * ctx_pair,
							 mem_access_env_t * env)
{
	VCPU *vcpu = ctx_pair->vcpu;
	hpt_va_t lin_addr;
	size_t copied;
	memprot_x86vmx_eptlock_read_lock(vcpu);

	/* Segmentation: logical address -> linear address */
	lin_addr = guestmem_desegment(vcpu, env->seg, env->gaddr, env->size,
								  env->mode, env->cpl);

	/* Paging */
	copied = 0;
	while (copied < env->size) {
		hpt_va_t gva = lin_addr + copied;
		size_t size = env->size - copied;
		// size_t old_size;
		hpt_va_t gpa;
		void *hva;
		spa_t spa = INVALID_SPADDR;

		/* Linear address -> guest physical address */
		if (vcpu->vmcs.guest_CR0 & CR0_PG) {
			hpt_pmeo_t pmeo;
			int ret = hptw_checked_get_pmeo(&pmeo, &ctx_pair->guest_ctx,
										    env->mode, env->cpl, gva);
			HALT_ON_ERRORCOND(ret == 0);
			gpa = hpt_pmeo_va_to_pa(&pmeo, gva);
			size = MIN(size, hpt_remaining_on_page(&pmeo, gpa));
		} else {
			gpa = gva;
		}

		// /* Guest physical address -> hypervisor physical address */
		// // old_size = size;
		// hva = hptw_checked_access_va(&ctx_pair->host_ctx, env->mode, env->cpl,
		// 							 gpa, size, &size);
		// if (hva == NULL) {
		// 	// /* Memory not in EPT, need special treatment */
		// 	// access_special_memory(vcpu, env->hvaddr + copied, env->mode,
		// 	// 					  env->cpl, gpa, old_size, &size);
		// 	// copied += size;
        //     return -1;
		// } else {
		// 	/* Perform normal memory access */
		// 	if (env->mode & HPT_PROT_WRITE_MASK) {
		// 		memcpy(hva, env->hvaddr + copied, size);
		// 	} else {
		// 		memcpy(env->hvaddr + copied, hva, size);
		// 	}
		// 	copied += size;
		// }

		spa = (spa_t)hptw_gpa_to_spa(&ctx_pair->host_ctx, gpa);
		hva = spa2hva(spa);

		if (hva == NULL) 
			return -1;
		else
		{
			/* Perform normal memory access */
			if (env->mode & HPT_PROT_WRITE_MASK) {
				memcpy(hva, env->hvaddr + copied, size);
			} else {
				memcpy(env->hvaddr + copied, hva, size);
			}
			copied += size;
		}
	}

	memprot_x86vmx_eptlock_read_unlock(vcpu);

    return 0;
}

/// @brief Rename <access_memory_gv>
/// @param ctx_pair 
/// @param env 
/// @return 
int x86_vmx_access_memory_gv(guestmem_hptw_ctx_pair_t * ctx_pair,
							 mem_access_env_t * env)
{
	return access_memory_gv(ctx_pair, env);
}

#define EXTEND(dtype, stype) \
	do { \
		_Static_assert(sizeof(dtype) >= sizeof(stype), "Type size mismatch"); \
		if (sizeof(dtype) == dst_size && sizeof(stype) == src_size) { \
			*(dtype *)dst = (dtype)*(stype *)src; \
			return; \
		} \
	} while (0)

static void zero_extend(void *dst, void *src, size_t dst_size, size_t src_size)
{
	EXTEND(uint8_t, uint8_t);
	EXTEND(uint16_t, uint8_t);
	EXTEND(uint32_t, uint8_t);
	EXTEND(uint64_t, uint8_t);
	EXTEND(uint16_t, uint16_t);
	EXTEND(uint32_t, uint16_t);
	EXTEND(uint64_t, uint16_t);
	EXTEND(uint32_t, uint32_t);
	EXTEND(uint64_t, uint32_t);
	EXTEND(uint64_t, uint64_t);
	HALT_ON_ERRORCOND(0 && "Unknown sizes");
}

static void sign_extend(void *dst, void *src, size_t dst_size, size_t src_size)
{
	EXTEND(int8_t, int8_t);
	EXTEND(int16_t, int8_t);
	EXTEND(int32_t, int8_t);
	EXTEND(int64_t, int8_t);
	EXTEND(int16_t, int16_t);
	EXTEND(int32_t, int16_t);
	EXTEND(int64_t, int16_t);
	EXTEND(int32_t, int32_t);
	EXTEND(int64_t, int32_t);
	EXTEND(int64_t, int64_t);
	HALT_ON_ERRORCOND(0 && "Unknown sizes");
}

#undef EXTEND

/* Given register index, return its pointer */
static void *get_reg_ptr(emu_env_t * emu_env, enum CPU_Reg_Sel index,
						 size_t size)
{
	if (size == BIT_SIZE_8) {
		HALT_ON_ERRORCOND(0 && "Not implemented");
		// Note: in 32-bit mode, AH CH DH BH are different
		// Note: in 64-bit mode, AH CH DH BH do not exist
	}
	switch (index) {
		case CPU_REG_AX: return &emu_env->r->eax;
		case CPU_REG_CX: return &emu_env->r->ecx;
		case CPU_REG_DX: return &emu_env->r->edx;
		case CPU_REG_BX: return &emu_env->r->ebx;
		case CPU_REG_SP: return &emu_env->vcpu->vmcs.guest_RSP;
		case CPU_REG_BP: return &emu_env->r->ebp;
		case CPU_REG_SI: return &emu_env->r->esi;
		case CPU_REG_DI: return &emu_env->r->edi;
#ifdef __AMD64__
		case CPU_REG_R8: return &emu_env->r->r8;
		case CPU_REG_R9: return &emu_env->r->r9;
		case CPU_REG_R10: return &emu_env->r->r10;
		case CPU_REG_R11: return &emu_env->r->r11;
		case CPU_REG_R12: return &emu_env->r->r12;
		case CPU_REG_R13: return &emu_env->r->r13;
		case CPU_REG_R14: return &emu_env->r->r14;
		case CPU_REG_R15: return &emu_env->r->r15;
#elif !defined(__I386__)
    #error "Unsupported Arch"
#endif /* !defined(__I386__) */
		default: HALT_ON_ERRORCOND(0 && "Invalid register");
	}
}

/* Return whether the operand size is 32 bits */
static size_t get_operand_size(emu_env_t * emu_env)
{
	if (emu_env->g64) {
		if (emu_env->prefix.rex.w) {
			return BIT_SIZE_64;
		} else {
			return emu_env->prefix.opsize ? BIT_SIZE_16 : BIT_SIZE_32;
		}
	} else {
		if (emu_env->prefix.opsize) {
			return emu_env->cs_d ? BIT_SIZE_16 : BIT_SIZE_32;
		} else {
			return emu_env->cs_d ? BIT_SIZE_32 : BIT_SIZE_16;
		}
	}
}

static int eval_operand_value(emu_env_t* emu_env, struct operand* op)
{
	if(op->type == OPERAND_REG)
	{
		memcpy(op->val, (void*)op->reg_hvaddr, op->operand_size);
	}
	else if (op->type == OPERAND_MEM)
	{
		int ret = 0;

		mem_access_env_t env = {
			.hvaddr = (void*)op->val,
			.gaddr = op->mem.offset,
			.seg = op->mem.seg,
			.size = op->operand_size,
			.mode = HPT_PROT_READ_MASK,
			.cpl = emu_env->vcpu->vmcs.guest_CS_selector & 3,
		};

		ret = access_memory_gv(&emu_env->ctx_pair, &env);
		if(ret)
		{
		    printf("Eval operand value error!\n");
		    return -1;
		}

	}
	else if (op->type == OPERAND_IMM)
	{
		u64 imm = 0;
		void *pimm = NULL;

		if (op->operand_size == BIT_SIZE_64) {
			imm = (int64_t)*(int32_t *)emu_env->postfix.immediate4;
			pimm = &imm;
		} else {
			pimm = emu_env->postfix.immediate;
		}

		memcpy(op->val, (void*)pimm, op->operand_size);
	}
	else
	{
		// Unsupported operand value type
		return -1;
	}

	// On success
	return 0;
}

/* Return whether the operand size is 32 bits */
static size_t get_address_size(emu_env_t * emu_env)
{
	if (emu_env->g64) {
		return emu_env->prefix.addrsize ? BIT_SIZE_32 : BIT_SIZE_64;
	}
	if (emu_env->prefix.addrsize) {
		return emu_env->cs_d ? BIT_SIZE_16 : BIT_SIZE_32;
	} else {
		return emu_env->cs_d ? BIT_SIZE_32 : BIT_SIZE_16;
	}
}

/* Return reg of ModRM, adjusted by REX prefix */
static u8 get_modrm_reg(emu_env_t * emu_env)
{
	u8 ans = emu_env->postfix.modrm.regop;
	if (emu_env->prefix.rex.four) {
		ans |= emu_env->prefix.rex.r << 3;
	}
	return ans;
}

/* Return rm of ModRM, adjusted by REX prefix */
static u8 get_modrm_rm(emu_env_t * emu_env)
{
	u8 ans = emu_env->postfix.modrm.rm;
	if (emu_env->prefix.rex.four) {
		ans |= emu_env->prefix.rex.b << 3;
	}
	return ans;
}

/* Return index of SIB, adjusted by REX prefix */
static u8 get_sib_index(emu_env_t * emu_env)
{
	u8 ans = emu_env->postfix.sib.index;
	if (emu_env->prefix.rex.four) {
		ans |= emu_env->prefix.rex.x << 3;
	}
	return ans;
}

/* Return base of SIB, adjusted by REX prefix */
static u8 get_sib_base(emu_env_t * emu_env)
{
	u8 ans = emu_env->postfix.sib.base;
	if (emu_env->prefix.rex.four) {
		ans |= emu_env->prefix.rex.b << 3;
	}
	return ans;
}

/* Return hypervisor memory address containing the register */
static void *eval_modrm_reg(emu_env_t * emu_env)
{
	size_t operand_size = get_operand_size(emu_env);
	return get_reg_ptr(emu_env, get_modrm_reg(emu_env), operand_size);
}

/*
 * Compute segment used for memory reference.
 * Ref: SDM volume 1, Table 3-5. Default Segment Selection Rules.
 */
static void compute_segment(emu_env_t * emu_env, enum CPU_Reg_Sel index)
{
	HALT_ON_ERRORCOND(emu_env->seg == CPU_SEG_UNKNOWN);
	if (emu_env->prefix.seg != CPU_SEG_UNKNOWN) {
		emu_env->seg = emu_env->prefix.seg;
	} else if (index == CPU_REG_BP || index == CPU_REG_SP) {
		emu_env->seg = CPU_SEG_SS;
	} else {
		emu_env->seg = CPU_SEG_DS;
	}
}

/* Return the value encoded by SIB */
static uintptr_t eval_sib_addr(emu_env_t * emu_env)
{
	size_t address_size = get_address_size(emu_env);
	size_t id = get_sib_index(emu_env);
	size_t bs = get_sib_base(emu_env);
	uintptr_t scaled_index = 0;
	uintptr_t base = 0;
	HALT_ON_ERRORCOND(address_size != BIT_SIZE_16 && "Not implemented");

	if (id != CPU_REG_SP) {
		zero_extend(&scaled_index, get_reg_ptr(emu_env, id, address_size),
					sizeof(scaled_index), address_size);
		scaled_index <<= emu_env->postfix.sib.scale;
	}

	if (!(emu_env->postfix.modrm.mod == 0 && bs % 8 == CPU_REG_BP)) {
		zero_extend(&base, get_reg_ptr(emu_env, bs, address_size),
					sizeof(base), address_size);
		compute_segment(emu_env, bs);
	} else {
		compute_segment(emu_env, CPU_REG_AX);
	}

	return scaled_index + base;
}

/*
 * If memory, return true and store guest memory address to addr.
 * If register, return false and store hypervisor memory address to addr.
 */
static bool eval_modrm_addr(emu_env_t * emu_env, uintptr_t *addr)
{
	size_t address_size = get_address_size(emu_env);
	HALT_ON_ERRORCOND(address_size != BIT_SIZE_16 && "Not implemented");

	/* Register operand, simple case */
	if (emu_env->postfix.modrm.mod == 3) {
		size_t operand_size = get_operand_size(emu_env);
		void *ans = get_reg_ptr(emu_env, get_modrm_rm(emu_env), operand_size);
		*addr = (uintptr_t)ans;
		return false;
	}

	/* Compute register / SIB */
	if (get_modrm_rm(emu_env) % 8 == CPU_REG_SP) {
		*addr = eval_sib_addr(emu_env);
	} else if (get_modrm_rm(emu_env) % 8 == CPU_REG_BP &&
			   emu_env->postfix.modrm.mod == 0) {
		HALT_ON_ERRORCOND(address_size != BIT_SIZE_64 &&
						  "Not implemented (RIP relative addressing)");
		*addr = 0;
		compute_segment(emu_env, CPU_REG_AX);
	} else {
		u8 rm = get_modrm_rm(emu_env);
		zero_extend(addr, get_reg_ptr(emu_env, rm, address_size), sizeof(addr),
					address_size);
		compute_segment(emu_env, rm);
	}

	/* Compute displacement */
	if (emu_env->displacement_len) {
		uintptr_t displacement;
		sign_extend(&displacement, emu_env->postfix.displacement,
					sizeof(displacement), emu_env->displacement_len);
		*addr += displacement;
	}

	/* Truncate result to address size */
	zero_extend(addr, addr, sizeof(*addr), address_size);

	return true;
}

/*
 * Read prefixes of instruction.
 * prefix should be initialized with PREFIX_INFO_INITIALIZER.
 */
static void parse_prefix(emu_env_t * emu_env)
{
	/* Group 1 - 4 */
	bool read_prefix;
	do {
		HALT_ON_ERRORCOND(emu_env->pinst_len > 0);
		read_prefix = true;
		switch (emu_env->pinst[0]) {
			case 0x26: emu_env->prefix.seg = CPU_SEG_ES; break;
			case 0x2e: emu_env->prefix.seg = CPU_SEG_CS; break;
			case 0x36: emu_env->prefix.seg = CPU_SEG_SS; break;
			case 0x3e: emu_env->prefix.seg = CPU_SEG_DS; break;
			case 0x64: emu_env->prefix.seg = CPU_SEG_FS; break;
			case 0x65: emu_env->prefix.seg = CPU_SEG_GS; break;
			case 0x66: emu_env->prefix.opsize = true; break;
			case 0x67: emu_env->prefix.addrsize = true; break;
			case 0xf0: emu_env->prefix.lock = true; break;
			case 0xf2: emu_env->prefix.repne = true; break;
			case 0xf3: emu_env->prefix.repe = true; break;
			default: read_prefix = false; break;
		}
		if (read_prefix) {
			emu_env->pinst++;
			emu_env->pinst_len--;
		}
	} while (read_prefix);

	/* REX */
	if (emu_env->g64 && (emu_env->pinst[0] & 0xf0) == 0x40) {
		emu_env->prefix.rex.raw = emu_env->pinst[0];
		emu_env->pinst++;
		emu_env->pinst_len--;
		HALT_ON_ERRORCOND(emu_env->pinst_len > 0);
	}
}

/* Parse parts of an instruction after the opcode */
static void parse_postfix(emu_env_t * emu_env, bool has_modrm, bool has_sib,
						  size_t displacement_len, size_t immediate_len)
{

#define SET_DISP(x) \
	do { \
		HALT_ON_ERRORCOND(displacement_len == 0); \
		displacement_len = (x); \
	} while (0)

#define SET_SIB(x) \
	do { \
		HALT_ON_ERRORCOND(!has_sib); \
		has_sib = (x); \
	} while (0)

	if (has_modrm) {
		HALT_ON_ERRORCOND(emu_env->pinst_len >= 1);
		emu_env->postfix.modrm.raw = emu_env->pinst[0];
		emu_env->pinst++;
		emu_env->pinst_len--;

		/* Compute displacement */
		switch (emu_env->postfix.modrm.mod) {
		case 0:
			switch (get_address_size(emu_env)) {
			case BIT_SIZE_16:
				if (get_modrm_rm(emu_env) == 6) {
					SET_DISP(BIT_SIZE_16);
				}
				break;
			case BIT_SIZE_32:	/* fallthrough */
			case BIT_SIZE_64:
				if (get_modrm_rm(emu_env) % 8 == CPU_REG_BP) {
					SET_DISP(BIT_SIZE_32);
				}
				break;
			default:
				HALT_ON_ERRORCOND(0 && "Invalid value");
			}
			break;
		case 1:
			SET_DISP(BIT_SIZE_8);
			break;
		case 2:
			SET_DISP(MIN(get_address_size(emu_env), BIT_SIZE_32));
			break;
		case 3:
			break;
		default:
			HALT_ON_ERRORCOND(0 && "Invalid value");
		}

		/* Compute whether SIB is present */
		if (emu_env->postfix.modrm.mod != 3 &&
			get_address_size(emu_env) != BIT_SIZE_16 &&
			get_modrm_rm(emu_env) % 8 == CPU_REG_SP) {
			SET_SIB(true);
		}
	}
	if (has_sib) {
		HALT_ON_ERRORCOND(emu_env->pinst_len >= 1);
		emu_env->postfix.sib.raw = emu_env->pinst[0];
		emu_env->pinst++;
		emu_env->pinst_len--;

		/* Compute displacement if mod=0, base=5 */
		if (emu_env->postfix.modrm.mod == 0 &&
			get_sib_base(emu_env) % 8 == CPU_REG_BP) {
			SET_DISP(BIT_SIZE_32);
		}
	}
	if (displacement_len > 0) {
		HALT_ON_ERRORCOND(emu_env->pinst_len >= displacement_len);
		emu_env->postfix.displacement = emu_env->pinst;
		emu_env->pinst += displacement_len;
		emu_env->pinst_len -= displacement_len;
	}
	if (immediate_len > 0) {
		HALT_ON_ERRORCOND(emu_env->pinst_len >= immediate_len);
		emu_env->postfix.immediate = emu_env->pinst;
		emu_env->pinst += immediate_len;
		emu_env->pinst_len -= immediate_len;
	}
	HALT_ON_ERRORCOND(emu_env->pinst_len == 0);

	emu_env->displacement_len = displacement_len;
	emu_env->immediate_len = immediate_len;

#undef SET_DISP
#undef SET_SIB

}

#define XMM_REG_SIZE    (16)
static void read_xmm0(void* buffer) 
{
    // Using raw opcode for `movaps [memory], xmm0`
    asm volatile(
        ".byte 0x0f, 0x29, 0x00" // 0F 29 /r MOVAPS m128, xmm1
        :
        : "r"(buffer)
        : "memory"
    );
}

#define _emu_unimplemented_inst_print(emu_env) \
	do { \
		printf("Guest instruction emulation error: Not implemented! line %d, file %s\n",  __LINE__, __FILE__); \
	} while (0)

/* Parse second byte of opcode starting with 0x0f */
static int parse_opcode_two_0f(emu_env_t * emu_env)
{
    int status = -1;
	u8 opcode;
	HALT_ON_ERRORCOND(emu_env->pinst_len > 0);
	opcode = emu_env->pinst[0];
	emu_env->pinst++;
	emu_env->pinst_len--;
	switch (opcode) {
	case 0x00: _emu_unimplemented_inst_print(emu_env); break;
	case 0x01: _emu_unimplemented_inst_print(emu_env); break;
	case 0x02: _emu_unimplemented_inst_print(emu_env); break;
	case 0x03: _emu_unimplemented_inst_print(emu_env); break;
	case 0x04: _emu_unimplemented_inst_print(emu_env); break;
	case 0x05: _emu_unimplemented_inst_print(emu_env); break;
	case 0x06: _emu_unimplemented_inst_print(emu_env); break;
	case 0x07: _emu_unimplemented_inst_print(emu_env); break;
	case 0x08: _emu_unimplemented_inst_print(emu_env); break;
	case 0x09: _emu_unimplemented_inst_print(emu_env); break;
	case 0x0a: _emu_unimplemented_inst_print(emu_env); break;
	case 0x0b: _emu_unimplemented_inst_print(emu_env); break;
	case 0x0c: _emu_unimplemented_inst_print(emu_env); break;
	case 0x0d: _emu_unimplemented_inst_print(emu_env); break;
	case 0x0e: _emu_unimplemented_inst_print(emu_env); break;
	case 0x0f: _emu_unimplemented_inst_print(emu_env); break;
	case 0x10: _emu_unimplemented_inst_print(emu_env); break;
	case 0x11:
    {
        // [TODO][Issue 137] This branch is called in <xmhf_memprot_emulate_guest_ring0_write>, so we only return the 
        // info needed by the caller.
        if((emu_env->pinst_len == 1) && 
            (emu_env->pinst[0] == 0x01)
        )
        {
            // movups xmmword ptr [rcx], xmm0
            uint8_t value[XMM_REG_SIZE] = {0};
            
            read_xmm0(value);

            emu_env->src.type = OPERAND_REG;
            emu_env->src.operand_size = XMM_REG_SIZE;
            memcpy(emu_env->src.val, value, XMM_REG_SIZE);
        }
        else if((emu_env->pinst_len == 2) &&
            (emu_env->pinst[0] == 0x04)
        )
        {
            // movups xmmword ptr [r12], xmm0
            uint8_t value[XMM_REG_SIZE] = {0};
            
            read_xmm0(value);

            emu_env->src.type = OPERAND_REG;
            emu_env->src.operand_size = XMM_REG_SIZE;
            memcpy(emu_env->src.val, value, XMM_REG_SIZE);
        }
        else if((emu_env->pinst_len == 1) && 
            (emu_env->pinst[0] == 0x00)
        )
        {
            // movups xmmword ptr [rax], xmm0
            uint8_t value[XMM_REG_SIZE] = {0};
            
            read_xmm0(value);

            emu_env->src.type = OPERAND_REG;
            emu_env->src.operand_size = XMM_REG_SIZE;
            memcpy(emu_env->src.val, value, XMM_REG_SIZE);
        }
        else
        {
            _emu_unimplemented_inst_print(emu_env); break;
        }

        // On success
        status = 0;

        break;
    }
	case 0x12: _emu_unimplemented_inst_print(emu_env); break;
	case 0x13: _emu_unimplemented_inst_print(emu_env); break;
	case 0x14: _emu_unimplemented_inst_print(emu_env); break;
	case 0x15: _emu_unimplemented_inst_print(emu_env); break;
	case 0x16: _emu_unimplemented_inst_print(emu_env); break;
	case 0x17: _emu_unimplemented_inst_print(emu_env); break;
	case 0x18: _emu_unimplemented_inst_print(emu_env); break;
	case 0x19: _emu_unimplemented_inst_print(emu_env); break;
	case 0x1a: _emu_unimplemented_inst_print(emu_env); break;
	case 0x1b: _emu_unimplemented_inst_print(emu_env); break;
	case 0x1c: _emu_unimplemented_inst_print(emu_env); break;
	case 0x1d: _emu_unimplemented_inst_print(emu_env); break;
	case 0x1e: _emu_unimplemented_inst_print(emu_env); break;
	case 0x1f: _emu_unimplemented_inst_print(emu_env); break;
	case 0x20: _emu_unimplemented_inst_print(emu_env); break;
	case 0x21: _emu_unimplemented_inst_print(emu_env); break;
	case 0x22: _emu_unimplemented_inst_print(emu_env); break;
	case 0x23: _emu_unimplemented_inst_print(emu_env); break;
	case 0x24: _emu_unimplemented_inst_print(emu_env); break;
	case 0x25: _emu_unimplemented_inst_print(emu_env); break;
	case 0x26: _emu_unimplemented_inst_print(emu_env); break;
	case 0x27: _emu_unimplemented_inst_print(emu_env); break;
	case 0x28: _emu_unimplemented_inst_print(emu_env); break;
	case 0x29: 
    {
        // [TODO][Issue 137] This branch is called in <xmhf_memprot_emulate_guest_ring0_write>, so we only return the 
        // info needed by the caller.
        if((emu_env->pinst_len == 1) && 
            (emu_env->pinst[0] == 0x01)
        )
        {
            // movaps xmmword ptr [rcx], xmm0
            uint8_t value[XMM_REG_SIZE] = {0};
            
            read_xmm0(value);

            emu_env->src.type = OPERAND_REG;
            emu_env->src.operand_size = XMM_REG_SIZE;
            memcpy(emu_env->src.val, value, XMM_REG_SIZE);
        }
        else if((emu_env->pinst_len == 2) && 
            (emu_env->pinst[0] == 0x41)
        )
        {
            // movaps xmmword ptr [rcx + 0x10], xmm0
            uint8_t value[XMM_REG_SIZE] = {0};
            
            read_xmm0(value);

            emu_env->src.type = OPERAND_REG;
            emu_env->src.operand_size = XMM_REG_SIZE;
            memcpy(emu_env->src.val, value, XMM_REG_SIZE);
        }
        else
        {
            _emu_unimplemented_inst_print(emu_env); break;
        }

        // On success
        status = 0;

        break;
    }
	case 0x2a: _emu_unimplemented_inst_print(emu_env); break;
	case 0x2b: _emu_unimplemented_inst_print(emu_env); break;
	case 0x2c: _emu_unimplemented_inst_print(emu_env); break;
	case 0x2d: _emu_unimplemented_inst_print(emu_env); break;
	case 0x2e: _emu_unimplemented_inst_print(emu_env); break;
	case 0x2f: _emu_unimplemented_inst_print(emu_env); break;
	case 0x30: _emu_unimplemented_inst_print(emu_env); break;
	case 0x31: _emu_unimplemented_inst_print(emu_env); break;
	case 0x32: _emu_unimplemented_inst_print(emu_env); break;
	case 0x33: _emu_unimplemented_inst_print(emu_env); break;
	case 0x34: _emu_unimplemented_inst_print(emu_env); break;
	case 0x35: _emu_unimplemented_inst_print(emu_env); break;
	case 0x36: _emu_unimplemented_inst_print(emu_env); break;
	case 0x37: _emu_unimplemented_inst_print(emu_env); break;
	case 0x38: _emu_unimplemented_inst_print(emu_env); break;
	case 0x39: _emu_unimplemented_inst_print(emu_env); break;
	case 0x3a: _emu_unimplemented_inst_print(emu_env); break;
	case 0x3b: _emu_unimplemented_inst_print(emu_env); break;
	case 0x3c: _emu_unimplemented_inst_print(emu_env); break;
	case 0x3d: _emu_unimplemented_inst_print(emu_env); break;
	case 0x3e: _emu_unimplemented_inst_print(emu_env); break;
	case 0x3f: _emu_unimplemented_inst_print(emu_env); break;
	case 0x40: _emu_unimplemented_inst_print(emu_env); break;
	case 0x41: _emu_unimplemented_inst_print(emu_env); break;
	case 0x42: _emu_unimplemented_inst_print(emu_env); break;
	case 0x43: _emu_unimplemented_inst_print(emu_env); break;
	case 0x44: _emu_unimplemented_inst_print(emu_env); break;
	case 0x45: _emu_unimplemented_inst_print(emu_env); break;
	case 0x46: _emu_unimplemented_inst_print(emu_env); break;
	case 0x47: _emu_unimplemented_inst_print(emu_env); break;
	case 0x48: _emu_unimplemented_inst_print(emu_env); break;
	case 0x49: _emu_unimplemented_inst_print(emu_env); break;
	case 0x4a: _emu_unimplemented_inst_print(emu_env); break;
	case 0x4b: _emu_unimplemented_inst_print(emu_env); break;
	case 0x4c: _emu_unimplemented_inst_print(emu_env); break;
	case 0x4d: _emu_unimplemented_inst_print(emu_env); break;
	case 0x4e: _emu_unimplemented_inst_print(emu_env); break;
	case 0x4f: _emu_unimplemented_inst_print(emu_env); break;
	case 0x50: _emu_unimplemented_inst_print(emu_env); break;
	case 0x51: _emu_unimplemented_inst_print(emu_env); break;
	case 0x52: _emu_unimplemented_inst_print(emu_env); break;
	case 0x53: _emu_unimplemented_inst_print(emu_env); break;
	case 0x54: _emu_unimplemented_inst_print(emu_env); break;
	case 0x55: _emu_unimplemented_inst_print(emu_env); break;
	case 0x56: _emu_unimplemented_inst_print(emu_env); break;
	case 0x57: _emu_unimplemented_inst_print(emu_env); break;
	case 0x58: _emu_unimplemented_inst_print(emu_env); break;
	case 0x59: _emu_unimplemented_inst_print(emu_env); break;
	case 0x5a: _emu_unimplemented_inst_print(emu_env); break;
	case 0x5b: _emu_unimplemented_inst_print(emu_env); break;
	case 0x5c: _emu_unimplemented_inst_print(emu_env); break;
	case 0x5d: _emu_unimplemented_inst_print(emu_env); break;
	case 0x5e: _emu_unimplemented_inst_print(emu_env); break;
	case 0x5f: _emu_unimplemented_inst_print(emu_env); break;
	case 0x60: _emu_unimplemented_inst_print(emu_env); break;
	case 0x61: _emu_unimplemented_inst_print(emu_env); break;
	case 0x62: _emu_unimplemented_inst_print(emu_env); break;
	case 0x63: _emu_unimplemented_inst_print(emu_env); break;
	case 0x64: _emu_unimplemented_inst_print(emu_env); break;
	case 0x65: _emu_unimplemented_inst_print(emu_env); break;
	case 0x66: _emu_unimplemented_inst_print(emu_env); break;
	case 0x67: _emu_unimplemented_inst_print(emu_env); break;
	case 0x68: _emu_unimplemented_inst_print(emu_env); break;
	case 0x69: _emu_unimplemented_inst_print(emu_env); break;
	case 0x6a: _emu_unimplemented_inst_print(emu_env); break;
	case 0x6b: _emu_unimplemented_inst_print(emu_env); break;
	case 0x6c: _emu_unimplemented_inst_print(emu_env); break;
	case 0x6d: _emu_unimplemented_inst_print(emu_env); break;
	case 0x6e: _emu_unimplemented_inst_print(emu_env); break;
	case 0x6f: _emu_unimplemented_inst_print(emu_env); break;
	case 0x70: _emu_unimplemented_inst_print(emu_env); break;
	case 0x71: _emu_unimplemented_inst_print(emu_env); break;
	case 0x72: _emu_unimplemented_inst_print(emu_env); break;
	case 0x73: _emu_unimplemented_inst_print(emu_env); break;
	case 0x74: _emu_unimplemented_inst_print(emu_env); break;
	case 0x75: _emu_unimplemented_inst_print(emu_env); break;
	case 0x76: _emu_unimplemented_inst_print(emu_env); break;
	case 0x77: _emu_unimplemented_inst_print(emu_env); break;
	case 0x78: _emu_unimplemented_inst_print(emu_env); break;
	case 0x79: _emu_unimplemented_inst_print(emu_env); break;
	case 0x7a: _emu_unimplemented_inst_print(emu_env); break;
	case 0x7b: _emu_unimplemented_inst_print(emu_env); break;
	case 0x7c: _emu_unimplemented_inst_print(emu_env); break;
	case 0x7d: _emu_unimplemented_inst_print(emu_env); break;
	case 0x7e: _emu_unimplemented_inst_print(emu_env); break;
	case 0x7f: 
    {
        // [TODO][Issue 137] This branch is called in <xmhf_memprot_emulate_guest_ring0_write>, so we only return the 
        // info needed by the caller.
        if((emu_env->pinst_len == 2) && 
            (emu_env->pinst[0] == 0x04) && (emu_env->pinst[1] == 0xc8)
        )
        {
            // movdqu xmmword ptr [eax + ecx*8], xmm0
            uint8_t value[XMM_REG_SIZE] = {0};
            
            read_xmm0(value);

            emu_env->src.type = OPERAND_REG;
            emu_env->src.operand_size = XMM_REG_SIZE;
            memcpy(emu_env->src.val, value, XMM_REG_SIZE);
        }
        else if((emu_env->pinst_len == 1) && 
            (emu_env->pinst[0] == 0x01)
        )
        {
            // movdqu xmmword ptr [rcx], xmm0
            uint8_t value[XMM_REG_SIZE] = {0};
            
            read_xmm0(value);

            emu_env->src.type = OPERAND_REG;
            emu_env->src.operand_size = XMM_REG_SIZE;
            memcpy(emu_env->src.val, value, XMM_REG_SIZE);
        }
        else
        {
            _emu_unimplemented_inst_print(emu_env); break;
        }

        // On success
        status = 0;

        break;
    }
	case 0x80: _emu_unimplemented_inst_print(emu_env); break;
	case 0x81: _emu_unimplemented_inst_print(emu_env); break;
	case 0x82: _emu_unimplemented_inst_print(emu_env); break;
	case 0x83: _emu_unimplemented_inst_print(emu_env); break;
	case 0x84: _emu_unimplemented_inst_print(emu_env); break;
	case 0x85: _emu_unimplemented_inst_print(emu_env); break;
	case 0x86: _emu_unimplemented_inst_print(emu_env); break;
	case 0x87: _emu_unimplemented_inst_print(emu_env); break;
	case 0x88: _emu_unimplemented_inst_print(emu_env); break;
	case 0x89: _emu_unimplemented_inst_print(emu_env); break;
	case 0x8a: _emu_unimplemented_inst_print(emu_env); break;
	case 0x8b: _emu_unimplemented_inst_print(emu_env); break;
	case 0x8c: _emu_unimplemented_inst_print(emu_env); break;
	case 0x8d: _emu_unimplemented_inst_print(emu_env); break;
	case 0x8e: _emu_unimplemented_inst_print(emu_env); break;
	case 0x8f: _emu_unimplemented_inst_print(emu_env); break;
	case 0x90: _emu_unimplemented_inst_print(emu_env); break;
	case 0x91: _emu_unimplemented_inst_print(emu_env); break;
	case 0x92: _emu_unimplemented_inst_print(emu_env); break;
	case 0x93: _emu_unimplemented_inst_print(emu_env); break;
	case 0x94: _emu_unimplemented_inst_print(emu_env); break;
	case 0x95: _emu_unimplemented_inst_print(emu_env); break;
	case 0x96: _emu_unimplemented_inst_print(emu_env); break;
	case 0x97: _emu_unimplemented_inst_print(emu_env); break;
	case 0x98: _emu_unimplemented_inst_print(emu_env); break;
	case 0x99: _emu_unimplemented_inst_print(emu_env); break;
	case 0x9a: _emu_unimplemented_inst_print(emu_env); break;
	case 0x9b: _emu_unimplemented_inst_print(emu_env); break;
	case 0x9c: _emu_unimplemented_inst_print(emu_env); break;
	case 0x9d: _emu_unimplemented_inst_print(emu_env); break;
	case 0x9e: _emu_unimplemented_inst_print(emu_env); break;
	case 0x9f: _emu_unimplemented_inst_print(emu_env); break;
	case 0xa0: _emu_unimplemented_inst_print(emu_env); break;
	case 0xa1: _emu_unimplemented_inst_print(emu_env); break;
	case 0xa2: _emu_unimplemented_inst_print(emu_env); break;
	case 0xa3: _emu_unimplemented_inst_print(emu_env); break;
	case 0xa4: _emu_unimplemented_inst_print(emu_env); break;
	case 0xa5: _emu_unimplemented_inst_print(emu_env); break;
	case 0xa6: _emu_unimplemented_inst_print(emu_env); break;
	case 0xa7: _emu_unimplemented_inst_print(emu_env); break;
	case 0xa8: _emu_unimplemented_inst_print(emu_env); break;
	case 0xa9: _emu_unimplemented_inst_print(emu_env); break;
	case 0xaa: _emu_unimplemented_inst_print(emu_env); break;
	case 0xab: _emu_unimplemented_inst_print(emu_env); break;
	case 0xac: _emu_unimplemented_inst_print(emu_env); break;
	case 0xad: _emu_unimplemented_inst_print(emu_env); break;
	case 0xae: _emu_unimplemented_inst_print(emu_env); break;
	case 0xaf: _emu_unimplemented_inst_print(emu_env); break;
	case 0xb0: _emu_unimplemented_inst_print(emu_env); break;
	case 0xb1: _emu_unimplemented_inst_print(emu_env); break;
	case 0xb2: _emu_unimplemented_inst_print(emu_env); break;
	case 0xb3: _emu_unimplemented_inst_print(emu_env); break;
	case 0xb4: _emu_unimplemented_inst_print(emu_env); break;
	case 0xb5: _emu_unimplemented_inst_print(emu_env); break;
	case 0xb6: _emu_unimplemented_inst_print(emu_env); break;
	case 0xb7: _emu_unimplemented_inst_print(emu_env); break;
	case 0xb8: _emu_unimplemented_inst_print(emu_env); break;
	case 0xb9: _emu_unimplemented_inst_print(emu_env); break;
	case 0xba:	/* BT/BTS/BTR/BTC Ev, Ib */
    {
		// TODO: LOCK is not implemented
        int ret = 0;
		emu_env->prefix.lock = true;
		HALT_ON_ERRORCOND(!emu_env->prefix.repe && "Not implemented");
		HALT_ON_ERRORCOND(!emu_env->prefix.repne && "Not implemented");
		parse_postfix(emu_env, true, false, 0, 1);
		{
			size_t operand_size = get_operand_size(emu_env);
			u8 imm = *emu_env->postfix.immediate1;
			u8 bit = imm % (operand_size * 8);
			uintptr_t rm;	/* r, w */
			uintptr_t value = 0;

			if (eval_modrm_addr(emu_env, &rm)) 
            {
				// Source is a memory
				uintptr_t guest_linear_addr = rm;
				mem_access_env_t env = {
					.hvaddr = &value,
					.gaddr = guest_linear_addr,
					.seg = emu_env->seg,
					.size = operand_size,
					.mode = HPT_PROT_READ_MASK,
					.cpl = emu_env->vcpu->vmcs.guest_CS_selector & 3,
				};

				emu_env->src.type = OPERAND_MEM;
				emu_env->src.operand_size = operand_size;
				emu_env->src.mem.seg = emu_env->seg;
				emu_env->src.mem.offset = guest_linear_addr;
				emu_env->src.mem.gvaddr = eval_guest_memory_gvaddr(&emu_env->ctx_pair, &env, guest_linear_addr);
				ret = eval_operand_value(emu_env, &emu_env->src);
				if(ret)
				{
					printf("[X86-VMX Emulator] Emulate BT/BTS/BTR/BTC read's memory error!\n");
					status = -1;
					goto L0xba_out;
				}


				// /* Read */
				// mem_access_env_t env = {
				// 	.hvaddr = &value,
				// 	.gaddr = rm,
				// 	.seg = emu_env->seg,
				// 	.size = operand_size,
				// 	.mode = HPT_PROT_READ_MASK,
				// 	.cpl = emu_env->vcpu->vmcs.guest_CS_selector & 3,
				// };
				// ret = access_memory_gv(&emu_env->ctx_pair, &env);
                // if(ret)
                // {
                //     printf("[X86-VMX Emulator] Emulate BT/BTS/BTR/BTC read error!\n");
                //     status = -1;
                //     goto L0xba_out;
                // }

				/* Store */
				if ((value >> bit) & 1) {
					emu_env->vcpu->vmcs.guest_RFLAGS |= EFLAGS_CF;
				} else {
					emu_env->vcpu->vmcs.guest_RFLAGS &= ~EFLAGS_CF;
				}
				/* Modify */
				switch (emu_env->postfix.modrm.regop) {
				case 4:	/* BT */
					break;
				case 5:	/* BTS */
					value |= (1UL << bit);
					break;
				case 6:	/* BTR */
					value &= ~(1UL << bit);
					break;
				case 7:	/* BTC */
					value ^= (1UL << bit);
					break;
				default:
					HALT_ON_ERRORCOND(0 && "Undefined opcode");
				}

				// Update emu_env->src.val
                memcpy(emu_env->src.val, &value, sizeof(uintptr_t));

				// Destination is the same as the source
				emu_env->dst.type = OPERAND_MEM;
				emu_env->dst.operand_size = operand_size;
				emu_env->dst.mem.seg = emu_env->seg;
				emu_env->dst.mem.offset = guest_linear_addr;
				emu_env->dst.mem.gvaddr = eval_guest_memory_gvaddr(&emu_env->ctx_pair, &env, guest_linear_addr);


				// /* Write */
				// env.mode = HPT_PROT_WRITE_MASK;
				// ret = access_memory_gv(&emu_env->ctx_pair, &env);
                // if(ret)
                // {
                //     printf("[X86-VMX Emulator] Emulate BT/BTS/BTR/BTC write error!\n");
                //     status = -1;
                //     goto L0xba_out;
                // }
			} else {
				HALT_ON_ERRORCOND(0 && "Not implemented");
			}
		}

        // On success
        status = 0;

L0xba_out:
        break;
    }
	case 0xbb: _emu_unimplemented_inst_print(emu_env); break;
	case 0xbc: _emu_unimplemented_inst_print(emu_env); break;
	case 0xbd: _emu_unimplemented_inst_print(emu_env); break;
	case 0xbe: _emu_unimplemented_inst_print(emu_env); break;
	case 0xbf: _emu_unimplemented_inst_print(emu_env); break;
	case 0xc0: _emu_unimplemented_inst_print(emu_env); break;
	case 0xc1: _emu_unimplemented_inst_print(emu_env); break;
	case 0xc2: _emu_unimplemented_inst_print(emu_env); break;
	case 0xc3: _emu_unimplemented_inst_print(emu_env); break;
	case 0xc4: _emu_unimplemented_inst_print(emu_env); break;
	case 0xc5: _emu_unimplemented_inst_print(emu_env); break;
	case 0xc6: _emu_unimplemented_inst_print(emu_env); break;
	case 0xc7: _emu_unimplemented_inst_print(emu_env); break;
	case 0xc8: _emu_unimplemented_inst_print(emu_env); break;
	case 0xc9: _emu_unimplemented_inst_print(emu_env); break;
	case 0xca: _emu_unimplemented_inst_print(emu_env); break;
	case 0xcb: _emu_unimplemented_inst_print(emu_env); break;
	case 0xcc: _emu_unimplemented_inst_print(emu_env); break;
	case 0xcd: _emu_unimplemented_inst_print(emu_env); break;
	case 0xce: _emu_unimplemented_inst_print(emu_env); break;
	case 0xcf: _emu_unimplemented_inst_print(emu_env); break;
	case 0xd0: _emu_unimplemented_inst_print(emu_env); break;
	case 0xd1: _emu_unimplemented_inst_print(emu_env); break;
	case 0xd2: _emu_unimplemented_inst_print(emu_env); break;
	case 0xd3: _emu_unimplemented_inst_print(emu_env); break;
	case 0xd4: _emu_unimplemented_inst_print(emu_env); break;
	case 0xd5: _emu_unimplemented_inst_print(emu_env); break;
	case 0xd6: _emu_unimplemented_inst_print(emu_env); break;
	case 0xd7: _emu_unimplemented_inst_print(emu_env); break;
	case 0xd8: _emu_unimplemented_inst_print(emu_env); break;
	case 0xd9: _emu_unimplemented_inst_print(emu_env); break;
	case 0xda: _emu_unimplemented_inst_print(emu_env); break;
	case 0xdb: _emu_unimplemented_inst_print(emu_env); break;
	case 0xdc: _emu_unimplemented_inst_print(emu_env); break;
	case 0xdd: _emu_unimplemented_inst_print(emu_env); break;
	case 0xde: _emu_unimplemented_inst_print(emu_env); break;
	case 0xdf: _emu_unimplemented_inst_print(emu_env); break;
	case 0xe0: _emu_unimplemented_inst_print(emu_env); break;
	case 0xe1: _emu_unimplemented_inst_print(emu_env); break;
	case 0xe2: _emu_unimplemented_inst_print(emu_env); break;
	case 0xe3: _emu_unimplemented_inst_print(emu_env); break;
	case 0xe4: _emu_unimplemented_inst_print(emu_env); break;
	case 0xe5: _emu_unimplemented_inst_print(emu_env); break;
	case 0xe6: _emu_unimplemented_inst_print(emu_env); break;
	case 0xe7: _emu_unimplemented_inst_print(emu_env); break;
	case 0xe8: _emu_unimplemented_inst_print(emu_env); break;
	case 0xe9: _emu_unimplemented_inst_print(emu_env); break;
	case 0xea: _emu_unimplemented_inst_print(emu_env); break;
	case 0xeb: _emu_unimplemented_inst_print(emu_env); break;
	case 0xec: _emu_unimplemented_inst_print(emu_env); break;
	case 0xed: _emu_unimplemented_inst_print(emu_env); break;
	case 0xee: _emu_unimplemented_inst_print(emu_env); break;
	case 0xef: _emu_unimplemented_inst_print(emu_env); break;
	case 0xf0: _emu_unimplemented_inst_print(emu_env); break;
	case 0xf1: _emu_unimplemented_inst_print(emu_env); break;
	case 0xf2: _emu_unimplemented_inst_print(emu_env); break;
	case 0xf3: _emu_unimplemented_inst_print(emu_env); break;
	case 0xf4: _emu_unimplemented_inst_print(emu_env); break;
	case 0xf5: _emu_unimplemented_inst_print(emu_env); break;
	case 0xf6: _emu_unimplemented_inst_print(emu_env); break;
	case 0xf7: _emu_unimplemented_inst_print(emu_env); break;
	case 0xf8: _emu_unimplemented_inst_print(emu_env); break;
	case 0xf9: _emu_unimplemented_inst_print(emu_env); break;
	case 0xfa: _emu_unimplemented_inst_print(emu_env); break;
	case 0xfb: _emu_unimplemented_inst_print(emu_env); break;
	case 0xfc: _emu_unimplemented_inst_print(emu_env); break;
	case 0xfd: _emu_unimplemented_inst_print(emu_env); break;
	case 0xfe: _emu_unimplemented_inst_print(emu_env); break;
	case 0xff: _emu_unimplemented_inst_print(emu_env); break;
	default:
		HALT_ON_ERRORCOND(0 && "Invalid opcode");
        status = -1;
		break;
	}

    return status;
}

/* Parse first byte of opcode */
// The definition of Ev, Gv, etc. is in Appendix A.2.1 of Intel SDM Volume 2
static int parse_opcode_one(emu_env_t * emu_env)
{
    int status = -1;
	u8 opcode;
	HALT_ON_ERRORCOND(emu_env->pinst_len > 0);
	opcode = emu_env->pinst[0];
	emu_env->pinst++;
	emu_env->pinst_len--;
	switch (opcode) {
	case 0x00: _emu_unimplemented_inst_print(emu_env); break;
	case 0x01: _emu_unimplemented_inst_print(emu_env); break;
	case 0x02: _emu_unimplemented_inst_print(emu_env); break;
	case 0x03: _emu_unimplemented_inst_print(emu_env); break;
	case 0x04: _emu_unimplemented_inst_print(emu_env); break;
	case 0x05: _emu_unimplemented_inst_print(emu_env); break;
	case 0x06: _emu_unimplemented_inst_print(emu_env); break;
	case 0x07: _emu_unimplemented_inst_print(emu_env); break;
	case 0x08: _emu_unimplemented_inst_print(emu_env); break;
	case 0x09: _emu_unimplemented_inst_print(emu_env); break;
	case 0x0a: _emu_unimplemented_inst_print(emu_env); break;
	case 0x0b: _emu_unimplemented_inst_print(emu_env); break;
	case 0x0c: _emu_unimplemented_inst_print(emu_env); break;
	case 0x0d: _emu_unimplemented_inst_print(emu_env); break;
	case 0x0e: _emu_unimplemented_inst_print(emu_env); break;
	case 0x0f:	/* 2-byte escape */
		status = parse_opcode_two_0f(emu_env);
		break;
	case 0x10: _emu_unimplemented_inst_print(emu_env); break;
	case 0x11: _emu_unimplemented_inst_print(emu_env); break;
	case 0x12: _emu_unimplemented_inst_print(emu_env); break;
	case 0x13: _emu_unimplemented_inst_print(emu_env); break;
	case 0x14: _emu_unimplemented_inst_print(emu_env); break;
	case 0x15: _emu_unimplemented_inst_print(emu_env); break;
	case 0x16: _emu_unimplemented_inst_print(emu_env); break;
	case 0x17: _emu_unimplemented_inst_print(emu_env); break;
	case 0x18: _emu_unimplemented_inst_print(emu_env); break;
	case 0x19: _emu_unimplemented_inst_print(emu_env); break;
	case 0x1a: _emu_unimplemented_inst_print(emu_env); break;
	case 0x1b: _emu_unimplemented_inst_print(emu_env); break;
	case 0x1c: _emu_unimplemented_inst_print(emu_env); break;
	case 0x1d: _emu_unimplemented_inst_print(emu_env); break;
	case 0x1e: _emu_unimplemented_inst_print(emu_env); break;
	case 0x1f: _emu_unimplemented_inst_print(emu_env); break;
	case 0x20: _emu_unimplemented_inst_print(emu_env); break;
	case 0x21: _emu_unimplemented_inst_print(emu_env); break;
	case 0x22: _emu_unimplemented_inst_print(emu_env); break;
	case 0x23: _emu_unimplemented_inst_print(emu_env); break;
	case 0x24: _emu_unimplemented_inst_print(emu_env); break;
	case 0x25: _emu_unimplemented_inst_print(emu_env); break;
	case 0x26: HALT_ON_ERRORCOND(0 && "Prefix operand"); break;
	case 0x27: _emu_unimplemented_inst_print(emu_env); break;
	case 0x28: _emu_unimplemented_inst_print(emu_env); break;
	case 0x29: _emu_unimplemented_inst_print(emu_env); break;
	case 0x2a: _emu_unimplemented_inst_print(emu_env); break;
	case 0x2b: _emu_unimplemented_inst_print(emu_env); break;
	case 0x2c: _emu_unimplemented_inst_print(emu_env); break;
	case 0x2d: _emu_unimplemented_inst_print(emu_env); break;
	case 0x2e: HALT_ON_ERRORCOND(0 && "Prefix operand"); break;
	case 0x2f: _emu_unimplemented_inst_print(emu_env); break;
	case 0x30: _emu_unimplemented_inst_print(emu_env); break;
	case 0x31: _emu_unimplemented_inst_print(emu_env); break;
	case 0x32: _emu_unimplemented_inst_print(emu_env); break;
	case 0x33: _emu_unimplemented_inst_print(emu_env); break;
	case 0x34: _emu_unimplemented_inst_print(emu_env); break;
	case 0x35: _emu_unimplemented_inst_print(emu_env); break;
	case 0x36: HALT_ON_ERRORCOND(0 && "Prefix operand"); break;
	case 0x37: _emu_unimplemented_inst_print(emu_env); break;
	case 0x38: _emu_unimplemented_inst_print(emu_env); break;
	case 0x39: _emu_unimplemented_inst_print(emu_env); break;
	case 0x3a: _emu_unimplemented_inst_print(emu_env); break;
	case 0x3b: _emu_unimplemented_inst_print(emu_env); break;
	case 0x3c: _emu_unimplemented_inst_print(emu_env); break;
	case 0x3d: _emu_unimplemented_inst_print(emu_env); break;
	case 0x3e: HALT_ON_ERRORCOND(0 && "Prefix operand"); break;
	case 0x3f: _emu_unimplemented_inst_print(emu_env); break;
	case 0x40: _emu_unimplemented_inst_print(emu_env); break;
	case 0x41: _emu_unimplemented_inst_print(emu_env); break;
	case 0x42: _emu_unimplemented_inst_print(emu_env); break;
	case 0x43: _emu_unimplemented_inst_print(emu_env); break;
	case 0x44: _emu_unimplemented_inst_print(emu_env); break;
	case 0x45: _emu_unimplemented_inst_print(emu_env); break;
	case 0x46: _emu_unimplemented_inst_print(emu_env); break;
	case 0x47: _emu_unimplemented_inst_print(emu_env); break;
	case 0x48: _emu_unimplemented_inst_print(emu_env); break;
	case 0x49: _emu_unimplemented_inst_print(emu_env); break;
	case 0x4a: _emu_unimplemented_inst_print(emu_env); break;
	case 0x4b: _emu_unimplemented_inst_print(emu_env); break;
	case 0x4c: _emu_unimplemented_inst_print(emu_env); break;
	case 0x4d: _emu_unimplemented_inst_print(emu_env); break;
	case 0x4e: _emu_unimplemented_inst_print(emu_env); break;
	case 0x4f: _emu_unimplemented_inst_print(emu_env); break;
	case 0x50: _emu_unimplemented_inst_print(emu_env); break;
	case 0x51: _emu_unimplemented_inst_print(emu_env); break;
	case 0x52: _emu_unimplemented_inst_print(emu_env); break;
	case 0x53: _emu_unimplemented_inst_print(emu_env); break;
	case 0x54: _emu_unimplemented_inst_print(emu_env); break;
	case 0x55: _emu_unimplemented_inst_print(emu_env); break;
	case 0x56: _emu_unimplemented_inst_print(emu_env); break;
	case 0x57: _emu_unimplemented_inst_print(emu_env); break;
	case 0x58: _emu_unimplemented_inst_print(emu_env); break;
	case 0x59: _emu_unimplemented_inst_print(emu_env); break;
	case 0x5a: _emu_unimplemented_inst_print(emu_env); break;
	case 0x5b: _emu_unimplemented_inst_print(emu_env); break;
	case 0x5c: _emu_unimplemented_inst_print(emu_env); break;
	case 0x5d: _emu_unimplemented_inst_print(emu_env); break;
	case 0x5e: _emu_unimplemented_inst_print(emu_env); break;
	case 0x5f: _emu_unimplemented_inst_print(emu_env); break;
	case 0x60: _emu_unimplemented_inst_print(emu_env); break;
	case 0x61: _emu_unimplemented_inst_print(emu_env); break;
	case 0x62: _emu_unimplemented_inst_print(emu_env); break;
	case 0x63: _emu_unimplemented_inst_print(emu_env); break;
	case 0x64: HALT_ON_ERRORCOND(0 && "Prefix operand"); break;
	case 0x65: HALT_ON_ERRORCOND(0 && "Prefix operand"); break;
	case 0x66: HALT_ON_ERRORCOND(0 && "Prefix operand"); break;
	case 0x67: HALT_ON_ERRORCOND(0 && "Prefix operand"); break;
	case 0x68: _emu_unimplemented_inst_print(emu_env); break;
	case 0x69: _emu_unimplemented_inst_print(emu_env); break;
	case 0x6a: _emu_unimplemented_inst_print(emu_env); break;
	case 0x6b: _emu_unimplemented_inst_print(emu_env); break;
	case 0x6c: _emu_unimplemented_inst_print(emu_env); break;
	case 0x6d: _emu_unimplemented_inst_print(emu_env); break;
	case 0x6e: _emu_unimplemented_inst_print(emu_env); break;
	case 0x6f: _emu_unimplemented_inst_print(emu_env); break;
	case 0x70: _emu_unimplemented_inst_print(emu_env); break;
	case 0x71: _emu_unimplemented_inst_print(emu_env); break;
	case 0x72: _emu_unimplemented_inst_print(emu_env); break;
	case 0x73: _emu_unimplemented_inst_print(emu_env); break;
	case 0x74: _emu_unimplemented_inst_print(emu_env); break;
	case 0x75: _emu_unimplemented_inst_print(emu_env); break;
	case 0x76: _emu_unimplemented_inst_print(emu_env); break;
	case 0x77: _emu_unimplemented_inst_print(emu_env); break;
	case 0x78: _emu_unimplemented_inst_print(emu_env); break;
	case 0x79: _emu_unimplemented_inst_print(emu_env); break;
	case 0x7a: _emu_unimplemented_inst_print(emu_env); break;
	case 0x7b: _emu_unimplemented_inst_print(emu_env); break;
	case 0x7c: _emu_unimplemented_inst_print(emu_env); break;
	case 0x7d: _emu_unimplemented_inst_print(emu_env); break;
	case 0x7e: _emu_unimplemented_inst_print(emu_env); break;
	case 0x7f: _emu_unimplemented_inst_print(emu_env); break;
	case 0x80: _emu_unimplemented_inst_print(emu_env); break;
	case 0x81: _emu_unimplemented_inst_print(emu_env); break;
	case 0x82: _emu_unimplemented_inst_print(emu_env); break;
	case 0x83: _emu_unimplemented_inst_print(emu_env); break;
	case 0x84: _emu_unimplemented_inst_print(emu_env); break;
	case 0x85: _emu_unimplemented_inst_print(emu_env); break;
	case 0x86: _emu_unimplemented_inst_print(emu_env); break;
	case 0x87: _emu_unimplemented_inst_print(emu_env); break;
	case 0x88: 
    {
        // [TODO][Issue 137] This branch is called in <xmhf_memprot_emulate_guest_ring0_write>, so we only return the 
        // info needed by the caller.
        if((emu_env->pinst_len == 3) && 
            (emu_env->pinst[0] == 0x44) && (emu_env->pinst[1] == 0xD1) && (emu_env->pinst[2] == 0x0C)
        )
        {
            // mov byte ptr [rcx + rdx*8 + 0xc], al
            // ulong_t cx = VCPU_reg_get(emu_env->vcpu, emu_env->r, CPU_REG_CX);
            // ulong_t dx = VCPU_reg_get(emu_env->vcpu, emu_env->r, CPU_REG_DX);
            uint8_t al = (uint8_t)VCPU_reg_get(emu_env->vcpu, emu_env->r, CPU_REG_AX);

            emu_env->src.type = OPERAND_REG;
            emu_env->src.operand_size = BIT_SIZE_8;
            memcpy(emu_env->src.val, &al, sizeof(uint8_t));
        }
        else if((emu_env->pinst_len == 2) && 
            (emu_env->pinst[0] == 0x47) && (emu_env->pinst[1] == 0x0C)
        )
        {
            // mov byte ptr [r15 + 0xc], al
            uint8_t al = (uint8_t)VCPU_reg_get(emu_env->vcpu, emu_env->r, CPU_REG_AX);

            emu_env->src.type = OPERAND_REG;
            emu_env->src.operand_size = BIT_SIZE_8;
            memcpy(emu_env->src.val, &al, sizeof(uint8_t));
        }
        else if((emu_env->pinst_len == 2) && 
            (emu_env->pinst[0] == 0x41) && (emu_env->pinst[1] == 0x0C)
        )
        {
            // mov byte ptr [rcx + 0xc], al
            uint8_t al = (uint8_t)VCPU_reg_get(emu_env->vcpu, emu_env->r, CPU_REG_AX);

            emu_env->src.type = OPERAND_REG;
            emu_env->src.operand_size = BIT_SIZE_8;
            memcpy(emu_env->src.val, &al, sizeof(uint8_t));
        }
        else
        {
            _emu_unimplemented_inst_print(emu_env); break;
        }

        // On success
        status = 0;

        break;
    }
	case 0x89:	/* MOV Ev, Gv */
    {
		HALT_ON_ERRORCOND(!emu_env->prefix.lock && "Not implemented");
		HALT_ON_ERRORCOND(!emu_env->prefix.repe && "Not implemented");
		HALT_ON_ERRORCOND(!emu_env->prefix.repne && "Not implemented");
		parse_postfix(emu_env, true, false, 0, 0);
		{
            int ret = 0;
			size_t operand_size = get_operand_size(emu_env);
			uintptr_t rm;	/* w */

			emu_env->src.type = OPERAND_REG;
			emu_env->src.reg_hvaddr = (hva_t)eval_modrm_reg(emu_env);	/* r */
			emu_env->src.operand_size = operand_size;
			ret = eval_operand_value(emu_env, &emu_env->src);
			if(ret)
			{
				printf("[X86-VMX Emulator] Emulate mov write's source operand error!\n");
				status = -1;
				goto L0x89_out;
			}

			if (eval_modrm_addr(emu_env, &rm)) 
			{
				// Destination is a memory
				uintptr_t guest_linear_addr = rm;
				mem_access_env_t env = {
					.hvaddr = (void*)emu_env->src.reg_hvaddr,
					.gaddr = guest_linear_addr,
					.seg = emu_env->seg,
					.size = operand_size,
					.mode = HPT_PROT_WRITE_MASK,
					.cpl = emu_env->vcpu->vmcs.guest_CS_selector & 3,
				};

				emu_env->dst.type = OPERAND_MEM;
				emu_env->dst.operand_size = operand_size;
				emu_env->dst.mem.seg = emu_env->seg;
				emu_env->dst.mem.offset = guest_linear_addr;
				emu_env->dst.mem.gvaddr = eval_guest_memory_gvaddr(&emu_env->ctx_pair, &env, guest_linear_addr);


				// ret = access_memory_gv(&emu_env->ctx_pair, &env);
                // if(ret)
                // {
                //     printf("[X86-VMX Emulator] Emulate mov write error!\n");
                //     status = -1;
                //     goto L0x89_out;
                // }
			} else {
				// Destination is a register
				emu_env->dst.type = OPERAND_REG;
				emu_env->dst.operand_size = operand_size;
				emu_env->dst.reg_hvaddr = rm;

				// memcpy((void *)rm, (void*)emu_env->src.reg_hvaddr, operand_size);
			}
		}

        // On success
        status = 0;

L0x89_out:
		break;
    }
	case 0x8a: _emu_unimplemented_inst_print(emu_env); break;
	case 0x8b:	/* MOV Gv, Ev */
    {
		HALT_ON_ERRORCOND(!emu_env->prefix.lock && "Not implemented");
		HALT_ON_ERRORCOND(!emu_env->prefix.repe && "Not implemented");
		HALT_ON_ERRORCOND(!emu_env->prefix.repne && "Not implemented");
		parse_postfix(emu_env, true, false, 0, 0);
		{
            int ret = 0;
			size_t operand_size = get_operand_size(emu_env);
			uintptr_t rm;	/* r */

			emu_env->dst.type = OPERAND_REG;
			emu_env->dst.operand_size = operand_size;
			emu_env->dst.reg_hvaddr = (hva_t)eval_modrm_reg(emu_env);	/* w */

			if (eval_modrm_addr(emu_env, &rm)) 
			{
				// Source is a memory
				uintptr_t guest_linear_addr = rm;
				mem_access_env_t env = {
					.hvaddr = (void*)emu_env->dst.reg_hvaddr,
					.gaddr = guest_linear_addr,
					.seg = emu_env->seg,
					.size = operand_size,
					.mode = HPT_PROT_READ_MASK,
					.cpl = emu_env->vcpu->vmcs.guest_CS_selector & 3,
				};

				emu_env->src.type = OPERAND_MEM;
				emu_env->src.operand_size = operand_size;
				emu_env->src.mem.seg = emu_env->seg;
				emu_env->src.mem.offset = guest_linear_addr;
				emu_env->src.mem.gvaddr = eval_guest_memory_gvaddr(&emu_env->ctx_pair, &env, guest_linear_addr);
				ret = eval_operand_value(emu_env, &emu_env->src);
				if(ret)
				{
					printf("[X86-VMX Emulator] Emulate mov read's memory source operand error!\n");
					status = -1;
					goto L0x8b_out;
				}


				// ret = access_memory_gv(&emu_env->ctx_pair, &env);
                // if(ret)
                // {
                //     printf("[X86-VMX Emulator] Emulate mov read error!\n");
                //     status = -1;
                //     goto L0x8b_out;
                // }
			} else {
				// Source is a register
				emu_env->src.type = OPERAND_REG;
				emu_env->src.operand_size = operand_size;
				emu_env->src.reg_hvaddr = rm;
				ret = eval_operand_value(emu_env, &emu_env->src);
				if(ret)
				{
					printf("[X86-VMX Emulator] Emulate mov read's register source operand error!\n");
					status = -1;
					goto L0x8b_out;
				}

				// memcpy(reg, (void *)rm, operand_size);
			}
		}

		// On success
        status = 0;

L0x8b_out:
		break;
    }
	case 0x8c: _emu_unimplemented_inst_print(emu_env); break;
	case 0x8d: _emu_unimplemented_inst_print(emu_env); break;
	case 0x8e: _emu_unimplemented_inst_print(emu_env); break;
	case 0x8f: _emu_unimplemented_inst_print(emu_env); break;
	case 0x90: _emu_unimplemented_inst_print(emu_env); break;
	case 0x91: _emu_unimplemented_inst_print(emu_env); break;
	case 0x92: _emu_unimplemented_inst_print(emu_env); break;
	case 0x93: _emu_unimplemented_inst_print(emu_env); break;
	case 0x94: _emu_unimplemented_inst_print(emu_env); break;
	case 0x95: _emu_unimplemented_inst_print(emu_env); break;
	case 0x96: _emu_unimplemented_inst_print(emu_env); break;
	case 0x97: _emu_unimplemented_inst_print(emu_env); break;
	case 0x98: _emu_unimplemented_inst_print(emu_env); break;
	case 0x99: _emu_unimplemented_inst_print(emu_env); break;
	case 0x9a: _emu_unimplemented_inst_print(emu_env); break;
	case 0x9b: _emu_unimplemented_inst_print(emu_env); break;
	case 0x9c: _emu_unimplemented_inst_print(emu_env); break;
	case 0x9d: _emu_unimplemented_inst_print(emu_env); break;
	case 0x9e: _emu_unimplemented_inst_print(emu_env); break;
	case 0x9f: _emu_unimplemented_inst_print(emu_env); break;
	case 0xa0:	/* MOV AL, Ob */
	case 0xa1:	/* MOV rAX, Ov */
	case 0xa2:	/* MOV Ob, AL */
	case 0xa3:	/* MOV Ov, rAX */
    {
		HALT_ON_ERRORCOND(!emu_env->prefix.lock && "Not implemented");
		HALT_ON_ERRORCOND(!emu_env->prefix.repe && "Not implemented");
		HALT_ON_ERRORCOND(!emu_env->prefix.repne && "Not implemented");
		{
            int ret = 0;
			size_t address_size = get_address_size(emu_env);
			size_t operand_size = (opcode & 1) ? get_operand_size(emu_env) : 1;
			mem_access_env_t env;
			uintptr_t guest_linear_addr = 0;

			emu_env->src.type = OPERAND_REG;
			emu_env->src.operand_size = operand_size;
			emu_env->src.reg_hvaddr = (hva_t)get_reg_ptr(emu_env, CPU_REG_AX, operand_size);
			ret = eval_operand_value(emu_env, &emu_env->src);
			if(ret)
			{
				printf("[X86-VMX Emulator] Emulate mov read's AX source operand error!\n");
				status = -1;
				goto L0xa3_out;
			}


			parse_postfix(emu_env, false, false, 0, address_size);
			compute_segment(emu_env, CPU_REG_AX);
			env = (mem_access_env_t){
				.hvaddr = get_reg_ptr(emu_env, CPU_REG_AX, operand_size),
				.gaddr = 0,
				.seg = emu_env->seg,
				.size = operand_size,
				.mode = (opcode & 2) ? HPT_PROT_WRITE_MASK : HPT_PROT_READ_MASK,
				.cpl = emu_env->vcpu->vmcs.guest_CS_selector & 3,
			};
			zero_extend(&env.gaddr, emu_env->postfix.immediate,
						sizeof(env.gaddr), address_size);

			guest_linear_addr = env.gaddr;
			emu_env->dst.type = OPERAND_MEM;
			emu_env->dst.operand_size = operand_size;
			emu_env->dst.mem.seg = emu_env->seg;
			emu_env->dst.mem.offset = guest_linear_addr;
			emu_env->dst.mem.gvaddr = eval_guest_memory_gvaddr(&emu_env->ctx_pair, &env, guest_linear_addr);

			// ret = access_memory_gv(&emu_env->ctx_pair, &env);
            // if(ret)
            // {
            //     printf("[X86-VMX Emulator] Emulate mov write offset error!\n");
            //     status = -1;
            //     goto L0xa3_out;
            // }
		}
        
        // On success
        status = 0;

L0xa3_out:
        break;
    }
	case 0xa4: _emu_unimplemented_inst_print(emu_env); break;
	case 0xa5: _emu_unimplemented_inst_print(emu_env); break;
	case 0xa6: _emu_unimplemented_inst_print(emu_env); break;
	case 0xa7: _emu_unimplemented_inst_print(emu_env); break;
	case 0xa8: _emu_unimplemented_inst_print(emu_env); break;
	case 0xa9: _emu_unimplemented_inst_print(emu_env); break;
	case 0xaa: _emu_unimplemented_inst_print(emu_env); break;
	case 0xab: _emu_unimplemented_inst_print(emu_env); break;
	case 0xac: _emu_unimplemented_inst_print(emu_env); break;
	case 0xad: _emu_unimplemented_inst_print(emu_env); break;
	case 0xae: _emu_unimplemented_inst_print(emu_env); break;
	case 0xaf: _emu_unimplemented_inst_print(emu_env); break;
	case 0xb0: _emu_unimplemented_inst_print(emu_env); break;
	case 0xb1: _emu_unimplemented_inst_print(emu_env); break;
	case 0xb2: _emu_unimplemented_inst_print(emu_env); break;
	case 0xb3: _emu_unimplemented_inst_print(emu_env); break;
	case 0xb4: _emu_unimplemented_inst_print(emu_env); break;
	case 0xb5: _emu_unimplemented_inst_print(emu_env); break;
	case 0xb6: _emu_unimplemented_inst_print(emu_env); break;
	case 0xb7: _emu_unimplemented_inst_print(emu_env); break;
	case 0xb8: _emu_unimplemented_inst_print(emu_env); break;
	case 0xb9: _emu_unimplemented_inst_print(emu_env); break;
	case 0xba: _emu_unimplemented_inst_print(emu_env); break;
	case 0xbb: _emu_unimplemented_inst_print(emu_env); break;
	case 0xbc: _emu_unimplemented_inst_print(emu_env); break;
	case 0xbd: _emu_unimplemented_inst_print(emu_env); break;
	case 0xbe: _emu_unimplemented_inst_print(emu_env); break;
	case 0xbf: _emu_unimplemented_inst_print(emu_env); break;
	case 0xc0: _emu_unimplemented_inst_print(emu_env); break;
	case 0xc1: _emu_unimplemented_inst_print(emu_env); break;
	case 0xc2: _emu_unimplemented_inst_print(emu_env); break;
	case 0xc3: _emu_unimplemented_inst_print(emu_env); break;
	case 0xc4: _emu_unimplemented_inst_print(emu_env); break;
	case 0xc5: _emu_unimplemented_inst_print(emu_env); break;
	case 0xc6: _emu_unimplemented_inst_print(emu_env); break;
	case 0xc7:	/* MOV Ev, Iz */
    {
		HALT_ON_ERRORCOND(!emu_env->prefix.lock && "Not implemented");
		HALT_ON_ERRORCOND(!emu_env->prefix.repe && "Not implemented");
		HALT_ON_ERRORCOND(!emu_env->prefix.repne && "Not implemented");
		if (emu_env->postfix.modrm.regop == 0) {
			int ret = 0;
			size_t operand_size = get_operand_size(emu_env);
			size_t imm_size = MIN(operand_size, BIT_SIZE_32);
			// u64 imm;
			// void *pimm;
			uintptr_t rm;	/* w */
			parse_postfix(emu_env, true, false, 0, imm_size);
			// if (operand_size == BIT_SIZE_64) {
			// 	imm = (int64_t)*(int32_t *)emu_env->postfix.immediate4;
			// 	pimm = &imm;
			// } else {
			// 	pimm = emu_env->postfix.immediate;
			// }

			emu_env->src.type = OPERAND_IMM;
			emu_env->src.operand_size = operand_size;
			ret = eval_operand_value(emu_env, &emu_env->src);
			if(ret)
			{
				printf("[X86-VMX Emulator] Emulate mov write's immediate source operand error!\n");
				status = -1;
				goto L0xc7_out;
			}

			if (eval_modrm_addr(emu_env, &rm)) 
			{
				// Destination is a memory
				uintptr_t guest_linear_addr = rm;
				mem_access_env_t env = {
					.hvaddr = (void *)NULL,
					.gaddr = guest_linear_addr,
					.seg = emu_env->seg,
					.size = operand_size,
					.mode = HPT_PROT_WRITE_MASK,
					.cpl = emu_env->vcpu->vmcs.guest_CS_selector & 3,
				};

				emu_env->dst.type = OPERAND_MEM;
				emu_env->dst.operand_size = operand_size;
				emu_env->dst.mem.seg = emu_env->seg;
				emu_env->dst.mem.offset = guest_linear_addr;
				emu_env->dst.mem.gvaddr = eval_guest_memory_gvaddr(&emu_env->ctx_pair, &env, guest_linear_addr);


				// ret = access_memory_gv(&emu_env->ctx_pair, &env);
                // if(ret)
                // {
                //     printf("[X86-VMX Emulator] Emulate mov write immediate error!\n");
                //     status = -1;
                //     goto L0xc7_out;
                // }
			} 
			else 
			{
				// Destination is a register
				emu_env->dst.type = OPERAND_REG;
				emu_env->dst.operand_size = operand_size;
				emu_env->dst.reg_hvaddr = rm;

				// memcpy((void *)rm, (void *)pimm, operand_size);
			}
		} else {
            printf("[X86-VMX Emulator] Unable to emulate instruction:\n");
            _print_instruction(emu_env->pinst, emu_env->pinst_len);
			HALT_ON_ERRORCOND(0 && "Not implemented");
		}

		// On success
        status = 0;

L0xc7_out:
        break;
    }
	case 0xc8: _emu_unimplemented_inst_print(emu_env); break;
	case 0xc9: _emu_unimplemented_inst_print(emu_env); break;
	case 0xca: _emu_unimplemented_inst_print(emu_env); break;
	case 0xcb: _emu_unimplemented_inst_print(emu_env); break;
	case 0xcc: _emu_unimplemented_inst_print(emu_env); break;
	case 0xcd: _emu_unimplemented_inst_print(emu_env); break;
	case 0xce: _emu_unimplemented_inst_print(emu_env); break;
	case 0xcf: _emu_unimplemented_inst_print(emu_env); break;
	case 0xd0: _emu_unimplemented_inst_print(emu_env); break;
	case 0xd1: _emu_unimplemented_inst_print(emu_env); break;
	case 0xd2: _emu_unimplemented_inst_print(emu_env); break;
	case 0xd3: _emu_unimplemented_inst_print(emu_env); break;
	case 0xd4: _emu_unimplemented_inst_print(emu_env); break;
	case 0xd5: _emu_unimplemented_inst_print(emu_env); break;
	case 0xd6: _emu_unimplemented_inst_print(emu_env); break;
	case 0xd7: _emu_unimplemented_inst_print(emu_env); break;
	case 0xd8: _emu_unimplemented_inst_print(emu_env); break;
	case 0xd9: _emu_unimplemented_inst_print(emu_env); break;
	case 0xda: _emu_unimplemented_inst_print(emu_env); break;
	case 0xdb: _emu_unimplemented_inst_print(emu_env); break;
	case 0xdc: _emu_unimplemented_inst_print(emu_env); break;
	case 0xdd: _emu_unimplemented_inst_print(emu_env); break;
	case 0xde: _emu_unimplemented_inst_print(emu_env); break;
	case 0xdf: _emu_unimplemented_inst_print(emu_env); break;
	case 0xe0: _emu_unimplemented_inst_print(emu_env); break;
	case 0xe1: _emu_unimplemented_inst_print(emu_env); break;
	case 0xe2: _emu_unimplemented_inst_print(emu_env); break;
	case 0xe3: _emu_unimplemented_inst_print(emu_env); break;
	case 0xe4: _emu_unimplemented_inst_print(emu_env); break;
	case 0xe5: _emu_unimplemented_inst_print(emu_env); break;
	case 0xe6: _emu_unimplemented_inst_print(emu_env); break;
	case 0xe7: _emu_unimplemented_inst_print(emu_env); break;
	case 0xe8: _emu_unimplemented_inst_print(emu_env); break;
	case 0xe9: _emu_unimplemented_inst_print(emu_env); break;
	case 0xea: _emu_unimplemented_inst_print(emu_env); break;
	case 0xeb: _emu_unimplemented_inst_print(emu_env); break;
	case 0xec: _emu_unimplemented_inst_print(emu_env); break;
	case 0xed: _emu_unimplemented_inst_print(emu_env); break;
	case 0xee: _emu_unimplemented_inst_print(emu_env); break;
	case 0xef: _emu_unimplemented_inst_print(emu_env); break;
	case 0xf0: HALT_ON_ERRORCOND(0 && "Prefix operand"); break;
	case 0xf1: _emu_unimplemented_inst_print(emu_env); break;
	case 0xf2: HALT_ON_ERRORCOND(0 && "Prefix operand"); break;
	case 0xf3: HALT_ON_ERRORCOND(0 && "Prefix operand"); break;
	case 0xf4: _emu_unimplemented_inst_print(emu_env); break;
	case 0xf5: _emu_unimplemented_inst_print(emu_env); break;
	case 0xf6: _emu_unimplemented_inst_print(emu_env); break;
	case 0xf7: _emu_unimplemented_inst_print(emu_env); break;
	case 0xf8: _emu_unimplemented_inst_print(emu_env); break;
	case 0xf9: _emu_unimplemented_inst_print(emu_env); break;
	case 0xfa: _emu_unimplemented_inst_print(emu_env); break;
	case 0xfb: _emu_unimplemented_inst_print(emu_env); break;
	case 0xfc: _emu_unimplemented_inst_print(emu_env); break;
	case 0xfd: _emu_unimplemented_inst_print(emu_env); break;
	case 0xfe: _emu_unimplemented_inst_print(emu_env); break;
	case 0xff: _emu_unimplemented_inst_print(emu_env); break;
	default:
		HALT_ON_ERRORCOND(0 && "Invalid opcode");
        status = -1;
		break;
	}

    return status;
}

static void _prefix_init(prefix_t* prefix)
{
	prefix->lock = false;
	prefix->repe = false;
	prefix->repne = false;
	prefix->seg = CPU_SEG_UNKNOWN;
	prefix->opsize = false;
	prefix->addrsize = false;
	prefix->rex.raw = 0;
}

static void _print_instruction(unsigned char* inst, uint32_t inst_len)
{
	uint32_t i = 0;

	FOREACH_S(i, inst_len, INST_LEN_MAX, 0, 1)
	{
		printf("%02X ", inst[i]);
	}
	printf("\n");
}

int x86_vmx_emulate_instruction(VCPU * vcpu, struct regs *r, emu_env_t* emu_env, unsigned char* inst, uint32_t inst_len)
{
    int ret = 0;

	// Check: Parameters must be valid
	if(!vcpu || !r || !emu_env || !inst || !inst_len)
		return -1;

    memset(emu_env, 0, sizeof(emu_env_t));

	emu_env->vcpu = vcpu;
	emu_env->r = r;
	_prefix_init(&emu_env->prefix);
	guestmem_init(vcpu, &emu_env->ctx_pair);
	emu_env->g64 = VCPU_g64(vcpu);
	emu_env->cs_d = !!(vcpu->vmcs.guest_CS_access_rights & (1 << 14));
	emu_env->seg = CPU_SEG_UNKNOWN;

	// /* Fetch instruction */
	// HALT_ON_ERRORCOND(inst_len < INST_LEN_MAX);
	// {
	// 	mem_access_env_t env = {
	// 		.hvaddr = inst,
	// 		.gaddr = rip,
	// 		.seg = CPU_SEG_CS,
	// 		.size = inst_len,
	// 		.mode = HPT_PROT_EXEC_MASK,
	// 		.cpl = vcpu->vmcs.guest_CS_selector & 3,
	// 	};

	// 	ret = access_memory_gv(&emu_env->ctx_pair, &env);
    //     if(ret)
    //     {
    //         printf("[X86-VMX Emulator] Failed to read current domain's instruction at gvaddr:0x%lX!\n", rip);
    //         goto read_inst_err;
    //     }
	// }
	// printf("CPU(0x%02x): emulation: %d 0x%llx\n", vcpu->id, inst_len,
	// 	   *(u64 *)inst);

	/* Parse prefix and opcode */
	emu_env->pinst = inst;
	emu_env->pinst_len = inst_len;

	parse_prefix(emu_env);
	ret = parse_opcode_one(emu_env);
    if(ret)
    {
		printf("[X86-VMX Emulator] Failed to emulate the instruction at gvaddr:0x%lX. Instruction: ", vcpu->vmcs.guest_RIP);
		_print_instruction(inst, inst_len);
        goto emu_inst_err;
    }

	// // TODO: Should not increase RIP if string instrcution
	// HALT_ON_ERRORCOND(!emu_env->prefix.repe && !emu_env->prefix.repne);
	// vcpu->vmcs.guest_RIP += inst_len;

    // On success
    return 0;

emu_inst_err:
// read_inst_err:
    return -1;
}