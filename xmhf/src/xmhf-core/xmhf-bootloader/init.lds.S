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

/*OUTPUT_FORMAT("pe-i386")*/
OUTPUT_ARCH(i386)
OUTPUT_FORMAT(elf32-i386)

ENTRY(init_start)

MEMORY
{
  all (rwxai) : ORIGIN = 0x1E00000, LENGTH = 100M /* length is arbitrary */
  debug (rwxai) : ORIGIN = 0, LENGTH = 1024M
  unaccounted (rwxai) : ORIGIN = 0, LENGTH = 0 /* see section .unaccounted at end */
}

SECTIONS
{
  . = 0x1E00000;
  .multiboot_header : {
    KEEP(*(.multiboot_header))
    *(.multiboot_header)
    . = ALIGN(4096);
  } = 0x9090

  .text : {
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
    *(.eh_frame)
    *(.bss)
    *(.bss.*)
    *(.rel.bss)
    *(.rel.bss.*)
    . = ALIGN(4096);
  } =0x9090

  .stack : {
    *(.stack)
    . = ALIGN(4096);
  } =0x9090

  /DISCARD/ : {
    *(.comment)
    *(.note.gnu.property)
    *(.gnu.build.attributes)
  }

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
