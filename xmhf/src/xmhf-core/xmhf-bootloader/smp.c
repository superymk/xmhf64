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

//------------------------------------------------------------------------------
//smp.c
//this module scans for multi-core/CPUs within the system and
//returns the number of cores/CPUs as well as their LAPIC id,
//version, base and BSP indications
//author: amit vasudevan (amitvasudevan@acm.org)
#include <xmhf.h>

//forward prototypes
static int mp_checksum(unsigned char *mp, int len);
static u32 mp_scan_config(u32 base, u32 length, MPFP **mpfp);
static u32 mp_getebda(void);
ACPI_RSDP * ACPIGetRSDP(void);

u32 _ACPIGetRSDPComputeChecksum(uintptr_t spaddr, size_t size);

//exposed interface to the outside world
//inputs: array of type PCPU and pointer to u32 which will
//receive the number of cores/CPUs in the system
//uefi_rsdp: RSDP pointer from UEFI, or NULL
//returns: 1 on success, 0 on any failure
u32 smp_getinfo(PCPU *pcpus, u32 *num_pcpus, void *uefi_rsdp){
	MPFP *mpfp;
	MPCONFTABLE *mpctable;

	ACPI_RSDP *rsdp;

#if 0
	ACPI_XSDT *xsdt;
	u32 n_xsdt_entries;
	u64 *xsdtentrylist;
#else
	ACPI_RSDT	*rsdt;
	u32 n_rsdt_entries;
	u32 *rsdtentrylist;
#endif

  ACPI_MADT *madt;
	u8 madt_found=0;
	u32 i;

	//we scan ACPI MADT and then the MP configuration table if one is
	//present, in that order!

	//if we get here it means that we did not find a MP table, so
	//we need to look at ACPI MADT. Logical cores on some machines
	//(e.g HP8540p laptop with Core i5) are reported only using ACPI MADT
	//and there is no MP structures on such systems!
	printf("Finding SMP info. via ACPI...\n");
	if (uefi_rsdp == NULL) {
		rsdp=(ACPI_RSDP *)ACPIGetRSDP();
	} else {
		rsdp = (ACPI_RSDP *)uefi_rsdp;
		HALT_ON_ERRORCOND(_ACPIGetRSDPComputeChecksum((uintptr_t)rsdp, 20) == 0);
	}
	if(!rsdp){
		printf("System is not ACPI Compliant, falling through...\n");
		goto fallthrough;
	}

	printf("ACPI RSDP at 0x%08lx\n", rsdp);

#if 0
	xsdt=(ACPI_XSDT *)(u32)rsdp->xsdtaddress;
	n_xsdt_entries=(u32)((xsdt->length-sizeof(ACPI_XSDT))/8);

	printf("ACPI XSDT at 0x%08x\n", xsdt);
  printf("	len=0x%08x, headerlen=0x%08x, numentries=%u\n",
			xsdt->length, sizeof(ACPI_XSDT), n_xsdt_entries);

  xsdtentrylist=(u64 *) ( (u32)xsdt + sizeof(ACPI_XSDT) );

	for(i=0; i< n_xsdt_entries; i++){
    madt=(ACPI_MADT *)( (u32)xsdtentrylist[i]);
    if(madt->signature == ACPI_MADT_SIGNATURE){
    	madt_found=1;
    	break;
    }
	}
#else
	rsdt=(ACPI_RSDT *)(uintptr_t)rsdp->rsdtaddress;
	n_rsdt_entries=(u32)((rsdt->length-sizeof(ACPI_RSDT))/4);

	printf("ACPI RSDT at 0x%08lx\n", rsdt);
    printf("	len=0x%08x, headerlen=0x%08x, numentries=%u\n",
			rsdt->length, sizeof(ACPI_RSDT), n_rsdt_entries);

    rsdtentrylist=(u32 *) ( (uintptr_t)rsdt + sizeof(ACPI_RSDT) );

	for(i=0; i< n_rsdt_entries; i++)
    {
        madt=(ACPI_MADT *)( (uintptr_t)rsdtentrylist[i]);
        if(madt->signature == ACPI_MADT_SIGNATURE){
            madt_found=1;
            break;
        }
	}

#endif


	if(!madt_found){
		printf("ACPI MADT not found, falling through...\n");
		goto fallthrough;
	}

	printf("ACPI MADT at 0x%08lx\n", madt);
	printf("	len=0x%08x, record-length=%u bytes\n", madt->length,
			madt->length - sizeof(ACPI_MADT));

	//scan through MADT APIC records to find processors
	*num_pcpus=0;
	{
		u32 madtrecordlength = madt->length - sizeof(ACPI_MADT);
		u32 madtcurrentrecordoffset=0;
		u32 i=0;
		u32 foundcores=0;

		do{
			ACPI_MADT_APIC *apicrecord = (ACPI_MADT_APIC *)((uintptr_t)madt + sizeof(ACPI_MADT) + madtcurrentrecordoffset);
            printf("rec type=0x%02x, length=%u bytes, flags=0x%08x, id=0x%02x\n", apicrecord->type,
                        apicrecord->length, apicrecord->flags, apicrecord->lapicid);

			if(apicrecord->type == 0x0 && (apicrecord->flags & 0x1))
            { 
                //processor record
		        foundcores=1;
				HALT_ON_ERRORCOND( *num_pcpus < MAX_PCPU_ENTRIES);
				i = *num_pcpus;
				pcpus[i].lapic_id = apicrecord->lapicid;
                pcpus[i].lapic_ver = 0;
                pcpus[i].lapic_base = madt->lapicaddress;

                if(i == 0)
                    pcpus[i].isbsp = 1;	//ACPI spec says that first processor entry MUST be BSP
                else
                    pcpus[i].isbsp = 0;

				*num_pcpus = *num_pcpus + 1;
			}
			madtcurrentrecordoffset += apicrecord->length;
		}while(madtcurrentrecordoffset < madtrecordlength);

		if(foundcores)
			return 1;
	}


fallthrough:
	//ok, ACPI detection failed proceed with MP table scan
	//we simply grab all the info from there as per
	//the intel MP spec.
	//look at 1K at start of conventional mem.
	//look at 1K at top of conventional mem
	//look at 1K starting at EBDA and
	//look at 64K starting at 0xF0000

	if( mp_scan_config(0x0, 0x400, &mpfp) ||
			mp_scan_config(639 * 0x400, 0x400, &mpfp) ||
			mp_scan_config(mp_getebda(), 0x400, &mpfp) ||
			mp_scan_config(0xF0000, 0x10000, &mpfp) ){

	    printf("MP table found at: 0x%08lx\n", mpfp);
  		printf("MP spec rev=0x%02x\n", mpfp->spec_rev);
  		printf("MP feature info1=0x%02x\n", mpfp->mpfeatureinfo1);
  		printf("MP feature info2=0x%02x\n", mpfp->mpfeatureinfo2);
  		printf("MP Configuration table at 0x%08x\n", mpfp->paddrpointer);

  		HALT_ON_ERRORCOND( mpfp->paddrpointer != 0 );
			mpctable = (MPCONFTABLE *)(uintptr_t)(mpfp->paddrpointer);
  		HALT_ON_ERRORCOND(mpctable->signature == MPCONFTABLE_SIGNATURE);

		  {//debug
		    int i;
		    printf("OEM ID: ");
		    for(i=0; i < 8; i++)
		      printf("%c", mpctable->oemid[i]);
		    printf("\n");
		    printf("Product ID: ");
		    for(i=0; i < 12; i++)
		      printf("%c", mpctable->productid[i]);
		    printf("\n");
		  }

		  printf("Entry count=%u\n", mpctable->entrycount);
		  printf("LAPIC base=0x%08x\n", mpctable->lapicaddr);

		  //now step through CPU entries in the MP-table to determine
		  //how many CPUs we have
		  *num_pcpus=0;

			{
		    int i;
		    uintptr_t addrofnextentry= (uintptr_t)mpctable + sizeof(MPCONFTABLE);

		    for(i=0; i < mpctable->entrycount; i++){
		      MPENTRYCPU *cpu = (MPENTRYCPU *)addrofnextentry;
		      if(cpu->entrytype != 0)
		        break;

		      if(cpu->cpuflags & 0x1){
 		        HALT_ON_ERRORCOND( *num_pcpus < MAX_PCPU_ENTRIES);
						printf("CPU (0x%08lx) #%u: lapic id=0x%02x, ver=0x%02x, cpusig=0x%08x\n",
		          cpu, i, cpu->lapicid, cpu->lapicver, cpu->cpusig);
		        pcpus[i].lapic_id = cpu->lapicid;
		        pcpus[i].lapic_ver = cpu->lapicver;
		        pcpus[i].lapic_base = mpctable->lapicaddr;
		        pcpus[i].isbsp = cpu->cpuflags & 0x2;
		        *num_pcpus = *num_pcpus + 1;
		      }

		      addrofnextentry += sizeof(MPENTRYCPU);
		    }
		  }


			return 1;
	}


	return 1;

}


static int mp_checksum(unsigned char *mp, int len){
	int sum = 0;

	while (len--)
  	sum += *mp++;

	return sum & 0xFF;
}


//returns 1 if MP table found and populates mpfp with MP table pointer
//returns 0 if no MP table and makes mpfp=NULL
static u32 mp_scan_config(u32 base, u32 length, MPFP **mpfp){
	u32 *bp = (u32 *)(uintptr_t)base;
  MPFP *mpf;

  printf("%s: Finding MP table from 0x%08lx for %u bytes\n",
                        __FUNCTION__, bp, length);

  while (length > 0) {
     mpf = (MPFP *)bp;
     if ((*bp == MPFP_SIGNATURE) &&
                    (mpf->length == 1) &&
                    !mp_checksum((unsigned char *)bp, 16) &&
                    ((mpf->spec_rev == 1)
                     || (mpf->spec_rev == 4))) {

                        printf("%s: found SMP MP-table at 0x%08lx\n",
                               __FUNCTION__, mpf);

												*mpfp = mpf;
                        return 1;
      }
     bp += 4;
     length -= 16;
  }

  *mpfp=0;
	return 0;
}


u32 mp_getebda(void){
  u16 ebdaseg;
  u32 ebdaphys;
  //get EBDA segment from 040E:0000h in BIOS data area
  ebdaseg= * ((u16 *)0x0000040E);
  //convert it to its 32-bit physical address
  ebdaphys=(u32)(ebdaseg * 16);
	return ebdaphys;
}

//------------------------------------------------------------------------------
u32 _ACPIGetRSDPComputeChecksum(uintptr_t spaddr, size_t size){
  char *p;
  char checksum=0;
  size_t i;

  p=(char *)spaddr;

  for(i=0; i< size; i++)
    checksum+= (char)(*(p+i));

  return (u32)checksum;
}

//get the physical address of the root system description pointer (rsdp)
//return 0 if not found
ACPI_RSDP * ACPIGetRSDP(void){
  u16 ebdaseg;
  u32 ebdaphys;
  u32 i, found=0;
  ACPI_RSDP *rsdp;

  //get EBDA segment from 040E:0000h in BIOS data area
  ebdaseg= * ((u16 *)0x0000040E);
  //convert it to its 32-bit physical address
  ebdaphys=(u32)(ebdaseg * 16);
  //search first 1KB of ebda for rsdp signature (8 bytes long)
  for(i=0; i < (1024-8); i+=16){
    rsdp=(ACPI_RSDP *)(uintptr_t)(ebdaphys+i);
    if(rsdp->signature == ACPI_RSDP_SIGNATURE){
      /* Check for truncation */
      HALT_ON_ERRORCOND((uintptr_t)rsdp == (uintptr_t)(u32)(uintptr_t)rsdp);
      if(!_ACPIGetRSDPComputeChecksum((uintptr_t)rsdp, 20)){
        found=1;
        break;
      }
    }
  }

  if(found)
    return rsdp;

  //search within BIOS areas 0xE0000 to 0xFFFFF
  for(i=0xE0000; i < (0xFFFFF-8); i+=16){
    rsdp=(ACPI_RSDP *)(uintptr_t)i;
    if(rsdp->signature == ACPI_RSDP_SIGNATURE){
      HALT_ON_ERRORCOND((uintptr_t)rsdp == (uintptr_t)(u32)(uintptr_t)rsdp);
      if(!_ACPIGetRSDPComputeChecksum((uintptr_t)rsdp, 20)){
        found=1;
        break;
      }
    }
  }

  if(found)
    return rsdp;

  return (ACPI_RSDP *)NULL;
}
//------------------------------------------------------------------------------
