/*
	Initialisation taken from Bertrik Sikken (bertrik@sikken.nl).
	Partially copied from Jim Lynch's tutorial
*/

#define MAMCR			*(volatile unsigned int *)0xE01FC000
#define MAMTIM		*(volatile unsigned int *)0xE01FC004

#define PLLCON		*(volatile unsigned int *)0xE01FC080
#define PLLCFG		*(volatile unsigned int *)0xE01FC084
#define PLLSTAT		*(volatile unsigned int *)0xE01FC088
#define PLLFEED		*(volatile unsigned int *)0xE01FC08C

#define VPBDIV		*(volatile unsigned int *)0xE01FC100

#define SCS_REG     *(volatile unsigned int *)0xE01FC1A0

void IRQ_Routine (void)   __attribute__ ((interrupt("IRQ")));
void FIQ_Routine (void)   __attribute__ ((interrupt("FIQ")));
void SWI_Routine (void)   __attribute__ ((interrupt("SWI")));
void UNDEF_Routine (void) __attribute__ ((interrupt("UNDEF")));


// Forward Prototypes
void Init2148(void);


/*  Stubs for various interrupts  */

void IRQ_Routine (void) {
	while (1) ;
}

void FIQ_Routine (void)  {
	while (1) ;
}


void SWI_Routine (void)  {
	while (1) ;
}


void UNDEF_Routine (void) {
	while (1) ;
}


/**********************************************************
                      Initialize
**********************************************************/

#define PLOCK 0x400

static void feed(void)
{
	PLLFEED = 0xAA;
	PLLFEED = 0x55;
}


void Init2148(void)
{


	// 				Setting the Phased Lock Loop (PLL)
	//               ----------------------------------
	//
	// Olimex LPC-P2148 has a 12.0000 mhz crystal
	//
	// We'd like the LPC2148 to run at 60 mhz (has to be an even multiple of crystal)
	//
	// According to the Philips LPC2148 manual:   M = cclk / Fosc	where:	M    = PLL multiplier (bits 0-4 of PLLCFG)
	//																		cclk = 60000000 hz
	//																		Fosc = 12000000 hz
	//
	// Solving:	M = 60000000 / 12000000 = 5
	//
	//			Note: M - 1 must be entered into bits 0-4 of PLLCFG (assign 4 to these bits)
	//
	//
	// The Current Controlled Oscilator (CCO) must operate in the range 156 mhz to 320 mhz
	//
	// According to the Philips LPC2148 manual:	Fcco = cclk * 2 * P    where:	Fcco = CCO frequency
	//																			cclk = 60000000 hz
	//																			P = PLL divisor (bits 5-6 of PLLCFG)
	//
	// Solving:	Fcco = 60000000 * 2 * P
	//			P = 2  (trial value)
	//			Fcco = 60000000 * 2 * 2
	//			Fcc0 = 240000000 hz    (good choice for P since it's within the 156 mhz to 320 mhz range)
	//
	// From Table 22 (page 34) of Philips LPC2148 manual    P = 2, PLLCFG bits 5-6 = 1  (assign 1 to these bits)
	//
	// Finally:      PLLCFG = 0  01  00100  =  0x24
	//
	// Final note: to load PLLCFG register, we must use the 0xAA followed 0x55 write sequence to the PLLFEED register
	//             this is done in the short function feed() below
	//

	// Setting Multiplier and Divider values
  PLLCFG = 0x24;
  feed();

	// Enabling the PLL */
	PLLCON = 0x1;
	feed();

	// Wait for the PLL to lock to set frequency
	while(!(PLLSTAT & PLOCK)) ;

	// Connect the PLL as the clock source
	PLLCON = 0x3;
	feed();

	// Enabling MAM and setting number of clocks used for Flash memory fetch
	MAMTIM = 0x3;
	MAMCR = 0x2;

	// Setting peripheral Clock (pclk) to System Clock (cclk)
	VPBDIV = 0x1;  //pclk == cclk

	// Initialize Port0 & Port1 as Fast
	SCS_REG = 0x3;
}
