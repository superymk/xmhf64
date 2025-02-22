#ifndef INCLUDED_xmhf_tlsfbits
#define INCLUDED_xmhf_tlsfbits

#if defined(__cplusplus)
#define xmhf_tlsf_decl inline
#else
#define xmhf_tlsf_decl static
#endif

/*
** Architecture-specific bit manipulation routines.
**
** xmhf_tlsf achieves O(1) cost for malloc and free operations by limiting
** the search for a free block to a free list of guaranteed size
** adequate to fulfill the request, combined with efficient free list
** queries using bitmasks and architecture-specific bit-manipulation
** routines.
**
** Most modern processors provide instructions to count leading zeroes
** in a word, find the lowest and highest set bit, etc. These
** specific implementations will be used when available, falling back
** to a reasonably efficient generic implementation.
**
** NOTE: xmhf_tlsf spec relies on ffs/fls returning value 0..31.
** ffs/fls return 1-32 by default, returning 0 for error.
*/

/*
** Detect whether or not we are building for a 32- or 64-bit (LP/LLP)
** architecture. There is no reliable portable method at compile-time.
*/
#if defined (__alpha__) || defined (__ia64__) || defined (__x86_64__) \
	|| defined (_WIN64) || defined (__LP64__) || defined (__LLP64__)
#define xmhf_tlsf_64BIT
#endif

/*
** gcc 3.4 and above have builtin support, specialized for architecture.
** Some compilers masquerade as gcc; patchlevel test filters them out.
*/
#if defined (__GNUC__) && (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)) \
	&& defined (__GNUC_PATCHLEVEL__)

xmhf_tlsf_decl int xmhf_tlsf_ffs(unsigned int word)
{
	return __builtin_ffs(word) - 1;
}

xmhf_tlsf_decl int xmhf_tlsf_fls(unsigned int word)
{
	const int bit = word ? 32 - __builtin_clz(word) : 0;
	return bit - 1;
}

#elif defined (_MSC_VER) && defined (_M_IX86) && (_MSC_VER >= 1400)
/* Microsoft Visual C++ 2005 support on x86 architectures. */

#include <intrin.h>

#pragma intrinsic(_BitScanReverse)
#pragma intrinsic(_BitScanForward)

xmhf_tlsf_decl int xmhf_tlsf_fls(unsigned int word)
{
	unsigned long index;
	return _BitScanReverse(&index, word) ? index : -1;
}

xmhf_tlsf_decl int xmhf_tlsf_ffs(unsigned int word)
{
	unsigned long index;
	return _BitScanForward(&index, word) ? index : -1;
}

#elif defined (_MSC_VER) && defined (_M_PPC)
/* Microsoft Visual C++ support on PowerPC architectures. */

#include <ppcintrinsics.h>

xmhf_tlsf_decl int xmhf_tlsf_fls(unsigned int word)
{
	const int bit = 32 - _CountLeadingZeros(word);
	return bit - 1;
}

xmhf_tlsf_decl int xmhf_tlsf_ffs(unsigned int word)
{
	const unsigned int reverse = word & (~word + 1);
	const int bit = 32 - _CountLeadingZeros(reverse);
	return bit - 1;
}

#elif defined (__ARMCC_VERSION)
/* RealView Compilation Tools for ARM */

xmhf_tlsf_decl int xmhf_tlsf_ffs(unsigned int word)
{
	const unsigned int reverse = word & (~word + 1);
	const int bit = 32 - __clz(reverse);
	return bit - 1;
}

xmhf_tlsf_decl int xmhf_tlsf_fls(unsigned int word)
{
	const int bit = word ? 32 - __clz(word) : 0;
	return bit - 1;
}

#elif defined (__ghs__)
/* Green Hills support for PowerPC */

#include <ppc_ghs.h>

xmhf_tlsf_decl int xmhf_tlsf_ffs(unsigned int word)
{
	const unsigned int reverse = word & (~word + 1);
	const int bit = 32 - __CLZ32(reverse);
	return bit - 1;
}

xmhf_tlsf_decl int xmhf_tlsf_fls(unsigned int word)
{
	const int bit = word ? 32 - __CLZ32(word) : 0;
	return bit - 1;
}

#else
/* Fall back to generic implementation. */

xmhf_tlsf_decl int xmhf_tlsf_fls_generic(unsigned int word)
{
	int bit = 32;

	if (!word) bit -= 1;
	if (!(word & 0xffff0000)) { word <<= 16; bit -= 16; }
	if (!(word & 0xff000000)) { word <<= 8; bit -= 8; }
	if (!(word & 0xf0000000)) { word <<= 4; bit -= 4; }
	if (!(word & 0xc0000000)) { word <<= 2; bit -= 2; }
	if (!(word & 0x80000000)) { word <<= 1; bit -= 1; }

	return bit;
}

/* Implement ffs in terms of fls. */
xmhf_tlsf_decl int xmhf_tlsf_ffs(unsigned int word)
{
	return xmhf_tlsf_fls_generic(word & (~word + 1)) - 1;
}

xmhf_tlsf_decl int xmhf_tlsf_fls(unsigned int word)
{
	return xmhf_tlsf_fls_generic(word) - 1;
}

#endif

/* Possibly 64-bit version of xmhf_tlsf_fls. */
#if defined (xmhf_tlsf_64BIT)
xmhf_tlsf_decl int xmhf_tlsf_fls_sizet(size_t size)
{
	int high = (int)(size >> 32);
	int bits = 0;
	if (high)
	{
		bits = 32 + xmhf_tlsf_fls(high);
	}
	else
	{
		bits = xmhf_tlsf_fls((int)size & 0xffffffff);

	}
	return bits;
}
#else
#define xmhf_tlsf_fls_sizet xmhf_tlsf_fls
#endif

#undef xmhf_tlsf_decl

#endif
