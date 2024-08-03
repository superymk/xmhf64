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

// Author: Miao Yu (superymk@cmu.edu)

/*
 *
 * Copyright (C) 2008 Advanced Micro Devices, Inc.
 * Copyright (C) 2008 Ulf Jordan <jordan@chalmers.se>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/// @file Support PCI 16550 serial cards
/// Only tested with PIO accesses only.
///
/// How to use:
/// (1) One should find the PIO base of the PCI-serial card first with "lspci -vvv"
/// (2) Modify the <baseaddr> in <cb_serial> with that PIO base
///
/// Note: One should be careful with multi-ports PCI-serial card, because the code initialize the first logical port only.

/// dbg-x86-uart.c is limited in supporting PCI-serial cards. For example, it does not support cards using MMIO only.

#include <xmhf.h>

struct cb_serial
{
#define CB_SERIAL_TYPE_IO_MAPPED 1
#define CB_SERIAL_TYPE_MEMORY_MAPPED 2
    u32 type;
    uintptr_t baseaddr; // SPADDR of the MMIO base or PIO of the PIO base
    u32 baud;
    u32 regwidth;

    /* Crystal or input frequency to the chip containing the UART.
     * Provide the board specific details to allow the payload to
     * initialize the chip containing the UART and make independent
     * decisions as to which dividers to select and their values
     * to eventually arrive at the desired console baud-rate. */
    u32 input_hertz;
};

#define IOBASE cb_serial.baseaddr

// [NOTE] We use <uintptr_t> instead of <hva_t> because this file is used by both xmhf-bootloader and xmhf-runtime and
// they may run with different micro-architectures (i.e., xmhf-bootloader in i386 and xmhf-runtime in amd64).
// <uberxmhf/Makefile.in> defines "BCFLAGS += -D__I386__ -D__XMHF_AMD64__", which means xmhf-bootloader's CFLAGS is 
// __I386__ and it is built for the amd64 xmhf-runtime.
// If using <hva_t>, xmhf-bootloader use 32-bit pointers but <hva_t> is 64-bit long per its definition in __XMHF_AMD64__.
#define MEMBASE ((uintptr_t)spa2hva(IOBASE))

static struct cb_serial cb_serial =
    {
        .type = CB_SERIAL_TYPE_IO_MAPPED,
        .baseaddr = DEBUG_PCI_SERIAL_PORT, // Qemu PCI 16550A is 0x6060
        .baud = 115200,
        .regwidth = 1};
static int serial_hardware_is_present = 0;
static int serial_is_mem_mapped = 0;

#define mfence() __asm__ __volatile__("mfence" : : : "memory")

/// @brief [NOTE] <write32> is NOT <writel>. <write32> takes uint32_t, but <writel> takes ulong_t.
/// @param addr
/// @param val
static void write32(uintptr_t addr, uint32_t val)
{
    *(volatile uint32_t *)addr = val;

    // Prevent reading stale values of other memory/register impacted from the given memory/register <addr>
    mfence();
}

// static void write16(uintptr_t addr, uint16_t val)
// {
//     *(volatile uint16_t *)addr = val;

//     // Prevent reading stale values of other memory/register impacted from the given memory/register <addr>
//     mfence();
// }

static void write8(uintptr_t addr, uint8_t val)
{
    *(volatile uint8_t *)addr = val;

    // Prevent reading stale values of other memory/register impacted from the given memory/register <addr>
    mfence();
}

/// @brief [NOTE] <read32> is NOT <readl>. <read32> returns uint32_t, but <readl> returns ulong_t.
/// @param addr
/// @return
static uint32_t read32(const uintptr_t addr)
{
    return *(volatile const uint32_t *)addr;
}

// static uint16_t read16(const uintptr_t addr)
// {
//     return *(volatile const uint16_t *)addr;
// }

static uint8_t read8(const uintptr_t addr)
{
    return *(volatile const uint8_t *)addr;
}

static uint8_t serial_read_reg(int offset)
{
    offset *= cb_serial.regwidth;

    if (!serial_is_mem_mapped)
        return inb(IOBASE + offset);
    else if (cb_serial.regwidth == 4)
        return read32(MEMBASE + offset) & 0xff;
    else
        return read8(MEMBASE + offset);
}

static void serial_write_reg(uint8_t val, int offset)
{
    offset *= cb_serial.regwidth;

    if (!serial_is_mem_mapped)
        outb(val, IOBASE + offset);
    else if (cb_serial.regwidth == 4)
        write32((MEMBASE + offset), val & 0xff);
    else
        write8((MEMBASE + offset), val);
}

// 8250 Programming manual: https://en.wikibooks.org/wiki/Serial_Programming/8250_UART_Programming
static void serial_hardware_init(int speed, int word_bits,
                                 int parity, int stop_bits)
{
    unsigned char reg;
    uint16_t divisor;

    /* Disable interrupts. */
    serial_write_reg(0, 0x01);

    /* Assert RTS and DTR. */
    serial_write_reg(3, 0x04);

    /* Set the divisor latch. */
    // reg = serial_read_reg(0x03);
    reg = 0;
    if (word_bits == 8)
    {
        reg |= 0x3; // Bit 0, 1 to be 1
    }
    if (parity == 0)
    {
        reg |= 0 << 3; // Bit 3, 4, 5 to be 0
    }
    if (stop_bits == 1)
    {
        reg |= 0 << 2; // Bit 2 to be 0
    }
    serial_write_reg(reg | 0x80, 0x03);

    /* Write the divisor. */
    divisor = 115200 / speed;
    serial_write_reg(divisor & 0xFF, 0x00);
    serial_write_reg(divisor >> 8, 0x01);

    /* Restore the previous value of the divisor.
     * And set 8 bits per character */
    serial_write_reg((reg & ~0x80) | 3, 0x03);

    (void)word_bits;
    (void)parity;
    (void)stop_bits;
}

void dbg_x86_uart_pci_init(char *params)
{
    serial_is_mem_mapped = (cb_serial.type == CB_SERIAL_TYPE_MEMORY_MAPPED);

    if (!serial_is_mem_mapped)
    {
        if ((inb(IOBASE + 0x05) == 0xFF) &&
            (inb(IOBASE + 0x06) == 0xFF))
        {
            // printf("IO space mapped serial not present.");
            return;
        }
    }

    serial_hardware_init(cb_serial.baud, 8, 0, 1);
    serial_hardware_is_present = 1;

    (void)params;
}

void dbg_x86_uart_pci_putc(char ch)
{
    if (!serial_hardware_is_present)
        return;
    // #if !CONFIG(LP_PL011_SERIAL_CONSOLE)
    while ((serial_read_reg(0x05) & 0x20) == 0)
        ;
    // #endif
    serial_write_reg((uint8_t)ch, 0x00);
    if (ch == '\n')
        dbg_x86_uart_pci_putc('\r');
}

// write string to serial port
void dbg_x86_uart_pci_putstr(const char *s)
{
	while (*s)
		dbg_x86_uart_pci_putc(*s++);
}