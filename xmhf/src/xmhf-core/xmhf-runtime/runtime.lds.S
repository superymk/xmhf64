/*
 * @XMHF_LICENSE_HEADER_START@
 *
 * eXtensible, Modular Hypervisor Framework (XMHF)
 * Copyright (c) 2009-2012 Carnegie Mellon University
 * Copyright (c) 2010-2012 VDG Inc.
 * Copyright (c) 2024 Eric Li
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

#include <xmhf.h>

/* gcc -m32 will define i386, but we do not want it */
#ifdef i386
#undef i386
#endif /* i386 */

#ifdef __I386__
OUTPUT_ARCH(i386)
OUTPUT_FORMAT(elf32-i386)
#elif defined(__AMD64__)
OUTPUT_ARCH(i386:x86-64)
OUTPUT_FORMAT(elf64-x86-64)
#else /* !defined(__I386__) && !defined(__AMD64__) */
#error "Unsupported Arch"
#endif /* !defined(__I386__) && !defined(__AMD64__) */

ENTRY(xmhf_runtime_entry)

MEMORY
{
#ifdef __UEFI_ALLOCATE_XMHF_RUNTIME_BSS_HIGH__
  all (rwxai) : ORIGIN = __TARGET_BASE, LENGTH = 256M /* length is arbitrary */
#else
  all (rwxai) : ORIGIN = __TARGET_BASE, LENGTH = 1024M /* length is arbitrary */
#endif // __UEFI_ALLOCATE_XMHF_RUNTIME_BSS_HIGH__
  debug (rwxai) : ORIGIN = 0, LENGTH = 1024M
  unaccounted (rwxai) : ORIGIN = 0, LENGTH = 0 /* see section .unaccounted at end */
}

SECTIONS
{
  . = __TARGET_BASE;

  .text : {
    KEEP(*(.s_rpb))
    *(.s_rpb)
    *(.text)
    *(.text.*)
    *(.rel.text)
    *(.rel.text.*)
    . = ALIGN(4096);
  } =0x9090

  .data : {
    *(.data)
    *(.data.*)
    *(.rel.data)
    *(.rel.data.*)
    *(.rodata)
    *(.rodata.*)
    *(.rel.rodata)
    *(.rel.rodata.*)
    *(.comment)
    *(.eh_frame) /* exception-metadata. might be able to discard */
    . = ALIGN(4);
    /* .xcph_table allows XMHF to handle exceptions in hypervisor mode. */
    _begin_xcph_table = .;
    KEEP(*(.xcph_table))
    *(.xcph_table)
    _end_xcph_table = .;

#ifdef __XMHF_PIE_RUNTIME__
    /* .rela.dyn allows XMHF runtime to be loaded as PIE. */
    . = ALIGN(16);
    _begin_rela_dyn = .;
    KEEP(*(.rela.*))
    *(.rela.*)
    _end_rela_dyn = .;

    /* Other sections that arise when compiling as PIE. */
    *(.interp)
    *(.dynsym)
    *(.dynstr)
    *(.hash)
    *(.gnu.hash)
    *(.dynamic)
#endif /* __XMHF_PIE_RUNTIME__ */

    _end_rt_data = .;
  } =0x9090

  /*
   * This section is marked as NOBITS in runtime.exe. Need to use
   * --set-section-flags in objcopy to include this section to runtime.bin
   */
  .bss : {
    . = ALIGN(4);
#ifdef __SKIP_RUNTIME_BSS__
    _begin_rt_bss = .;
#endif /* __SKIP_RUNTIME_BSS__ */
    *(.bss)
    *(SORT_BY_ALIGNMENT(.bss.*))
    *(.rel.bss)
    *(.rel.bss.*)
#ifdef __SKIP_RUNTIME_BSS__
    _end_rt_bss = .;
#endif /* __SKIP_RUNTIME_BSS__ */
    . = ALIGN(4096);
  } =0x9090

  /* debug sections */
  .debug_abbrev : { *(.debug_abbrev) } >debug
  .debug_aranges : { *(.debug_aranges) } >debug
  .debug_info : { *(.debug_info) } >debug
  .debug_line : { *(.debug_line) } >debug
  .debug_line_str : { *(.debug_line_str) } >debug
  .debug_loc : { *(.debug_loc) } >debug
  .debug_loclists : { *(.debug_loclists) } >debug
  .debug_ranges : { *(.debug_ranges) } >debug
  .debug_rnglists : { *(.debug_rnglists) } >debug
  .debug_str : { *(.debug_str) } >debug
  .rel.debug_info : { *(.rel.debug_info) } >debug
  .rel.debug_aranges : { *(.rel.debug_aranges) } >debug
  .rel.debug_line : { *(.rel.debug_line) } >debug

#ifdef __XMHF_PIE_RUNTIME__
  /* Other sections that arise when compiling as PIE. */
  .shstrtab : { *(.shstrtab) } >debug
  .strtab : { *(.strtab) } >debug
  .symtab : { *(.symtab) } >debug
#endif /* __XMHF_PIE_RUNTIME__ */

  /DISCARD/ : {
    *(.note.gnu.property)
    *(.gnu.build.attributes)
  }

  /* this is to cause the link to fail if there is
   * anything we didn't explicitly place.
   * when this does cause link to fail, temporarily comment
   * this part out to see what sections end up in the output
   * which are not handled above, and handle them.
   */
  .unaccounted : {
    *(*)
  } >unaccounted

}
