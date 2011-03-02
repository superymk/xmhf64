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
 * This file is part of the EMHF historical reference
 * codebase, and is released under the terms of the
 * GNU General Public License (GPL) version 2.
 * Please see the LICENSE file for details.
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

#ifndef SCODE_H
#define SCODE_H

#include <stdint.h>
#include <stddef.h>

/* defined for scode sections info */
extern unsigned int __scode_util_start, __scode_util_end;

/* FIXME: copied from paging.h in trustvisor. should use that directly */
#define PAGE_SIZE 0x1000
#define PAGE_SIZE_4K (1UL << 12)
#define PAGE_ALIGN_UP4K(size)   (((size) + PAGE_SIZE_4K - 1) & ~(PAGE_SIZE_4K - 1))
#define PAGE_ALIGN_4K(size)     ((size) & ~(PAGE_SIZE_4K - 1))

#ifndef IS_VMX
#define VMCALL "vmmcall\n\t"
#else
#define VMCALL "vmcall\n\t"
#endif

enum VMMcmd
  {
    VMM_REG = 1,
    VMM_UNREG = 2,
    VMM_SEAL =3,
    VMM_UNSEAL =4,
    VMM_QUOTE =5,
    VMM_TEST = 255,
  };

enum scode_param_type
  {
    SCODE_PARAM_TYPE_INTEGER = 1,
    SCODE_PARAM_TYPE_POINTER = 2
  };

struct scode_params_struct{
  enum scode_param_type type;
  size_t size; /* in int's */
};

#define SCODE_MAX_PARAMS_NUM 10
struct scode_params_info{
  int params_num;
  struct scode_params_struct pm_str[SCODE_MAX_PARAMS_NUM];
};

enum scode_section_type
  {
    SCODE_SECTION_TYPE_SCODE = 1,
    SCODE_SECTION_TYPE_SDATA = 2,
    SCODE_SECTION_TYPE_PARAM = 3,
    SCODE_SECTION_TYPE_STACK = 4,
    SCODE_SECTION_TYPE_STEXT = 5
  };
struct scode_sections_struct{
  enum scode_section_type type;
  unsigned int start_addr;
  int page_num; /* size of section in pages */
};

#define SCODE_MAX_SECTION_NUM 10  /* max sections that are allowed in scode registration */
struct scode_sections_info{
  int section_num;
  struct scode_sections_struct ps_str[SCODE_MAX_SECTION_NUM];
};

/* read (and optionally write) to the memory pages in the specified
 * range. use this to make sure pages are present for trustvisor
 * (e.g., for pointer parameters before calling a pal function)
 */
int scode_touch_range(void *ptr, size_t len, int do_write);

/* convenience function for getting size of a section from end and start symbols */
size_t scode_ptr_diff(void *end, void *start);

/* initialize an scode_sections_info struct, allocating page-aligned memory
 * for the parameters and stack.
 */
void scode_sections_info_init(struct scode_sections_info *scode_info,
                              void *scode, size_t scode_len,
                              void *sdata, size_t sdata_len,
                              size_t param_sz,
                              size_t stack_sz);

/* add a section to an scode_sections_info struct.
 * The struct should have already been initialized.
 */
void scode_sections_info_add(struct scode_sections_info *scode_info,
                             int type,
                             void *start_addr, size_t len);

/* Print scode_sections_info to stdout */
void scode_sections_info_print(struct scode_sections_info *scode_info);

/* Register a PAL.
 * pageinfo describes the memory areas to be used by the PAL.
 *   FIXME: preconditions? e.g., mandatory vs optional sections?
 * params describes the parameters to the PAL function.
 * entry is a pointer to the PAL function.
 *
 * Once a function is registered, any call to that function
 * will take place in the secure environment.
 *
 * Returns 0 on success, nonzero on failure.
 */
int scode_register(const struct scode_sections_info *pageinfo,
                   const struct scode_params_info *params,
                   const void *entry);

/* Unregister a PAL.
 * entry is a pointer to a function previously registered
 *   with scode_register
 *
 * After unregistration, calls to the given function
 * no longer take place in the secure environment.
 *
 * Returns 0 on success, nonzero on failure.
 */
int scode_unregister(void *entry);

/* Test for presence of TrustVisor.
 *
 * Returns 0 on success, nonzero on failure.
 */
int scode_test(void);

#endif
