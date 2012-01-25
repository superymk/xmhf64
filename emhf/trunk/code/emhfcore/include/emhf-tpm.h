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

// EMHF TPM component declarations
// author: amit vasudevan (amitvasudevan@acm.org)

#ifndef __EMHF_TPM_H__
#define __EMHF_TPM_H__


#ifndef __ASSEMBLY__


//----------------------------------------------------------------------
//exported DATA 
//----------------------------------------------------------------------


//----------------------------------------------------------------------
//exported FUNCTIONS 
//----------------------------------------------------------------------

//open TPM locality
int emhf_tpm_open_locality(int locality);

//check if TPM is ready for use
bool emhf_tpm_is_tpm_ready(uint32_t locality);

//----------------------------------------------------------------------
//ARCH. BACKENDS
//----------------------------------------------------------------------

//open TPM locality
int emhf_tpm_arch_open_locality(int locality);

//check if TPM is ready for use
bool emhf_tpm_arch_is_tpm_ready(uint32_t locality);


//----------------------------------------------------------------------
//x86 ARCH. INTERFACES
//----------------------------------------------------------------------

#define TPM_VALIDATE_LOCALITY_TIME_OUT  0x100

/*
 * TPM registers and data structures
 *
 * register values are offsets from each locality base
 * see {read,write}_tpm_reg() for data struct format
 */

/* TPM_ACCESS_x */
#define TPM_REG_ACCESS           0x00
typedef union {
    u8 _raw[1];                      /* 1-byte reg */
    struct __attribute__ ((packed)) {
        u8 tpm_establishment   : 1;  /* RO, 0=T/OS has been established
                                        before */
        u8 request_use         : 1;  /* RW, 1=locality is requesting TPM use */
        u8 pending_request     : 1;  /* RO, 1=other locality is requesting
                                        TPM usage */
        u8 seize               : 1;  /* WO, 1=seize locality */
        u8 been_seized         : 1;  /* RW, 1=locality seized while active */
        u8 active_locality     : 1;  /* RW, 1=locality is active */
        u8 reserved            : 1;
        u8 tpm_reg_valid_sts   : 1;  /* RO, 1=other bits are valid */
    };
} tpm_reg_access_t;

/* TPM_STS_x */
#define TPM_REG_STS              0x18
typedef union {
    u8 _raw[3];                  /* 3-byte reg */
    struct __attribute__ ((packed)) {
        u8 reserved1       : 1;
        u8 response_retry  : 1;  /* WO, 1=re-send response */
        u8 reserved2       : 1;
        u8 expect          : 1;  /* RO, 1=more data for command expected */
        u8 data_avail      : 1;  /* RO, 0=no more data for response */
        u8 tpm_go          : 1;  /* WO, 1=execute sent command */
        u8 command_ready   : 1;  /* RW, 1=TPM ready to receive new cmd */
        u8 sts_valid       : 1;  /* RO, 1=data_avail and expect bits are
                                    valid */
        u16 burst_count    : 16; /* RO, # read/writes bytes before wait */
    };
} tpm_reg_sts_t;

/* TPM_DATA_FIFO_x */
#define TPM_REG_DATA_FIFO        0x24
typedef union {
        uint8_t _raw[1];                      /* 1-byte reg */
} tpm_reg_data_fifo_t;

/*
 * assumes that all reg types follow above format:
 *   - packed
 *   - member named '_raw' which is array whose size is that of data to read
 */
#define read_tpm_reg(locality, reg, pdata)      \
    _read_tpm_reg(locality, reg, (pdata)->_raw, sizeof(*(pdata)))

#define write_tpm_reg(locality, reg, pdata)     \
    _write_tpm_reg(locality, reg, (pdata)->_raw, sizeof(*(pdata)))


/*********************************************************************
 * Moved in from tboot's tpm.c; I think it belongs in a .h file. Also
 * facilitates split into tpm.c and tpm_extra.c.
 *********************************************************************/

/* TODO: Give these a more appropriate home */
/* #define readb(va)       (*(volatile uint8_t *) (va)) */
/* #define writeb(va, d)   (*(volatile uint8_t *) (va) = (d)) */

#ifndef __EMHF_VERIFICATION__
static inline void writeb(u32 addr, u8 val) {
    __asm__ __volatile__("movb %%al, %%fs:(%%ebx)\r\n"
                         :
                         : "b"(addr), "a"((u32)val)
                         );
}

static inline u8 readb(u32 addr) {
    u32 ret;
    __asm__ __volatile("xor %%eax, %%eax\r\n"        
                       "movb %%fs:(%%ebx), %%al\r\n"
                       : "=a"(ret)
                       : "b"(addr)
                       );
    return (u8)ret;        
}
#endif	//__EMHF_VERIFICATION__

//TPM timeouts
#define TIMEOUT_UNIT    (0x100000 / 330) /* ~1ms, 1 tpm r/w need > 330ns */
#define TIMEOUT_A       750  /* 750ms */
#define TIMEOUT_B       2000 /* 2s */
#define TIMEOUT_C       750  /* 750ms */
#define TIMEOUT_D       750  /* 750ms */

typedef struct __attribute__ ((packed)) {
    uint32_t timeout_a;
    uint32_t timeout_b;
    uint32_t timeout_c;
    uint32_t timeout_d;
} tpm_timeout_t;


#define TPM_ACTIVE_LOCALITY_TIME_OUT    \
          (TIMEOUT_UNIT * g_timeout.timeout_a)  /* according to spec */
#define TPM_CMD_READY_TIME_OUT          \
          (TIMEOUT_UNIT * g_timeout.timeout_b)  /* according to spec */
#define TPM_CMD_WRITE_TIME_OUT          \
          (TIMEOUT_UNIT * g_timeout.timeout_d)  /* let it long enough */
#define TPM_DATA_AVAIL_TIME_OUT         \
          (TIMEOUT_UNIT * g_timeout.timeout_c)  /* let it long enough */
#define TPM_RSP_READ_TIME_OUT           \
          (TIMEOUT_UNIT * g_timeout.timeout_d)  /* let it long enough */



//----------------------------------------------------------------------
//x86vmx SUBARCH. INTERFACES
//----------------------------------------------------------------------
//open TPM locality
int emhf_tpm_arch_x86vmx_open_locality(int locality);


//----------------------------------------------------------------------
//x86vmx SUBARCH. INTERFACES
//----------------------------------------------------------------------
//open TPM locality
int emhf_tpm_arch_x86svm_open_locality(int locality);


#endif	//__ASSEMBLY__

#endif //__EMHF_TPM_H__

