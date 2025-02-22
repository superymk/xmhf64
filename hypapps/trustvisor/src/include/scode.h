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

/* scode.h - Module specific definitions
 * Written for TrustVisor by Ning Qu and Mark Luk
 * Edited by Zongwei Zhou for EMHF project
 */

#ifndef __SCODE_H_
#define __SCODE_H_

#include <xmhf.h>

#include <pages.h>

#include <trustvisor.h>
#include <crypto_init.h>
#include <tv_utpm.h> /* formerly utpm.h */

#include <perf.h>

#include <hpt.h>
#include <hptw.h>
#include <hpt_emhf.h>	/* from libemhfutil */
#include <hptw_emhf.h>

/* XXX TEMP */
#define CHK(x) HALT_ON_ERRORCOND(x)
#define CHK_RV(x) HALT_ON_ERRORCOND(!(x))

/*
 * definition for scode whitelist
 * */
/* in order to support 4GB memory */
#define  PFN_BITMAP_LIMIT 512*1024
#define  PFN_BITMAP_2M_LIMIT 2*1024

/* TODO: separate perf ctrs from scode.* */
extern perf_ctr_t g_tv_perf_ctrs[];
extern char *g_tv_perf_ctr_strings[];
#define TV_PERF_CTR_NPF 0
#define TV_PERF_CTR_SWITCH_SCODE 1
#define TV_PERF_CTR_SWITCH_REGULAR 2
#define TV_PERF_CTR_SAFEMALLOC 3
#define TV_PERF_CTR_MARSHALL 4
#define	TV_PERF_CTR_EXPOSE_ARCH 5
#define TV_PERF_CTR_NESTED_SWITCH_SCODE 6
/* insert new counters here, and update count below */
#define TV_PERF_CTRS_COUNT 7

typedef struct {
  hpt_va_t reg_gva;
  hpt_va_t pal_gva;
  size_t size;
  hpt_prot_t pal_prot;
  hpt_prot_t reg_prot;
  u32 section_type;
} tv_pal_section_int_t;

/* scode state struct */
typedef struct whitelist_entry{
  u64       gcr3;
  u32       id;
  bool      g64;        /* whether running in 64-bit mode */
  gpa_t     ept12;      /* NULL when L1, EPT12 when L2 */
  /* The fields above need to match when searching for a PAL */

  uintptr_t grsp;       /* guest reguar stack */
  uintptr_t gssp;       /* guest sensitive code stack */
  uintptr_t gss_size;   /* guest sensitive code stack page number */
  uintptr_t entry_v; /* entry point virtual address */
  uintptr_t entry_p; /* entry point physical address */
  uintptr_t return_v; /* return point virtual address */

  uintptr_t gpmp;     /* guest parameter page address */
  uintptr_t gpm_size; /* guest parameter page number */
  u64       gpm_num;  /* guest parameter number */

  hpt_pa_t  saved_pt_root_pa; /* regular EPT / NPT root (EPT02 when L2 guest) */
  hpt_pa_t  saved_pt_l1l2_root_pa; /* When nested virtualization, EPT12 */
  hptw_emhf_host_ctx_t saved_hptw_reg_host_ctx; /* ctx to walk EPT / NPT */
  u32 saved_exception_intercepts;
  bool saved_cr0_em; /* Save whether CR0.EM bit is set */
  bool saved_nested_intr_exit; /* Save VCPU_disable_nested_interrupt_exit() */
  u32 saved_nested_timer; /* Save VCPU_disable_nested_timer_exit() */
  u32 saved_nested_mem_bitmap; /* Save VCPU_disable_memory_bitmap() */

  tv_pal_section_int_t sections[TV_MAX_SECTIONS];
  size_t sections_num;

  struct tv_pal_sections scode_info; /* scode_info struct for registration function inpu */
  struct tv_pal_params params_info; /* param info struct */
  pte_t* scode_pages; /* registered pte's (copied from guest page tables and additional info added) */

  pte_t * pte_page;  /* holder for guest page table entry to access scode and GDT */
//#ifdef __MP_VERSION__
  u32 pal_running_lock; /* PAL running lock */
  u32 pal_running_vcpu_id; /* the cpu that is running this PAL */
//#endif

  /* Micro-TPM related */
  utpm_master_state_t utpm;

  /* pal page tables */
  pagelist_t *gpl;
  pagelist_t *npl;
  hptw_emhf_host_ctx_t hptw_pal_host_ctx;
  hptw_emhf_checked_guest_ctx_t hptw_pal_checked_guest_ctx;

  hpt_pa_t reg_gpt_root_pa;
  hpt_type_t reg_gpt_type;

  u64 pal_gcr3;
} __attribute__ ((packed)) whitelist_entry_t;

/* max size of memory that holds scode state */
#define WHITELIST_LIMIT (sizeof(whitelist_entry_t)*100)

/* nested paging handlers (hpt) */
hpt_prot_t pal_prot_of_type(int type);
hpt_prot_t reg_prot_of_type(int type);

/* operations from hypervisor to guest paging */
int copy_from_current_guest(VCPU * vcpu, void *dst, gva_t gvaddr, size_t len);

int copy_to_current_guest(VCPU * vcpu, gva_t gvaddr, void *src, size_t len);

/* PAL operations (HPT) */
u32 hpt_scode_switch_scode(VCPU * vcpu, struct regs *r);
u32 hpt_scode_switch_regular(VCPU * vcpu, struct regs *r);
u32 hpt_scode_npf(VCPU * vcpu, uintptr_t gpaddr, u64 errorcode, struct regs *r);
bool hpt_scode_is_scode(VCPU * vcpu);
int hpt_scode_get_scode_id(VCPU * vcpu);
void hpt_scode_destroy_all(void);
u32 scode_share(VCPU * vcpu, u32 scode_entry, u32 addr, u32 len);
u32 scode_share_ranges(VCPU * vcpu, u32 scode_entry, u32 gva_base[], u32 gva_len[], u32 count);

u64 scode_register(VCPU * vcpu, u64 scode_info, u64 scode_pm, u64 gventry);
u64 scode_unregister(VCPU * vcpu, u64 gvaddr);
void init_scode(VCPU * vcpu);

void scode_lend_section( hptw_ctx_t *reg_npm02_ctx,
                         hptw_ctx_t *reg_npm01_ctx,
                         bool is_nested_ept,
                         hptw_ctx_t *reg_gpm_ctx,
                         hptw_ctx_t *pal_npm_ctx,
                         hptw_ctx_t *pal_gpm_ctx,
                         const tv_pal_section_int_t *section);
void scode_return_section( hptw_ctx_t *reg_npm_ctx,
                           hptw_ctx_t *pal_npm_ctx,
                           hptw_ctx_t *pal_gpm_ctx,
                           const tv_pal_section_int_t *section);

#if 0
int scode_clone_gdt(VCPU *vcpu,
                    gva_t gdtr_base, size_t gdtr_lim,
                    hptw_ctx_t *pal_gpm_ctx,
                    pagelist_t *pl
                    );
#endif

#endif /* __SCODE_H_ */

/* Local Variables: */
/* mode:c           */
/* indent-tabs-mode:nil */
/* c-basic-offset:2 */
/* End:             */
