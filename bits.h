/*
 * bits.h -- Bit manipulation abstractions
 *
 * Copyright (c) 2006-2016, Matthew Conte
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef TLSF_BITS_H
#define TLSF_BITS_H

#include "macros.h"

/*
** Architecture-specific bit manipulation routines.
**
** TLSF achieves O(1) cost for malloc and free operations by limiting
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
** NOTE: TLSF spec relies on ffs/fls returning value 0..31.
** ffs/fls return 1-32 by default, returning 0 for error.
*/

/*
** gcc 3.4 and above have builtin support, specialized for architecture.
** Some compilers masquerade as gcc; patchlevel test filters them out.
*/
#if defined (__GNUC__) && (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)) \
      && defined (__GNUC_PATCHLEVEL__)

#if defined (__SNC__)
/* SNC for Playstation 3. */

static tlsf_always_inline int tlsf_ffs(unsigned int word)
{
  const unsigned int reverse = word & (~word + 1);
  const int bit = 32 - __builtin_clz(reverse);
  return bit - 1;
}

#else

static tlsf_always_inline int tlsf_ffs(unsigned int word)
{
  return __builtin_ffs(word) - 1;
}

#endif

static tlsf_always_inline int tlsf_fls(unsigned int word)
{
  const int bit = word ? 32 - __builtin_clz(word) : 0;
  return bit - 1;
}

#elif defined (_MSC_VER) && (_MSC_VER >= 1400) && (defined (_M_IX86) || defined (_M_X64))
/* Microsoft Visual C++ support on x86/X64 architectures. */

#include <intrin.h>

#pragma intrinsic(_BitScanReverse)
#pragma intrinsic(_BitScanForward)

static tlsf_always_inline int tlsf_fls(unsigned int word)
{
  unsigned long index;
  return _BitScanReverse(&index, word) ? index : -1;
}

static tlsf_always_inline int tlsf_ffs(unsigned int word)
{
  unsigned long index;
  return _BitScanForward(&index, word) ? index : -1;
}

#elif defined (_MSC_VER) && defined (_M_PPC)
/* Microsoft Visual C++ support on PowerPC architectures. */

#include <ppcintrinsics.h>

static tlsf_always_inline int tlsf_fls(unsigned int word)
{
  const int bit = 32 - _CountLeadingZeros(word);
  return bit - 1;
}

static tlsf_always_inline int tlsf_ffs(unsigned int word)
{
  const unsigned int reverse = word & (~word + 1);
  const int bit = 32 - _CountLeadingZeros(reverse);
  return bit - 1;
}

#elif defined (__ARMCC_VERSION)
/* RealView Compilation Tools for ARM */

static tlsf_always_inline int tlsf_ffs(unsigned int word)
{
  const unsigned int reverse = word & (~word + 1);
  const int bit = 32 - __clz(reverse);
  return bit - 1;
}

static tlsf_always_inline int tlsf_fls(unsigned int word)
{
  const int bit = word ? 32 - __clz(word) : 0;
  return bit - 1;
}

#elif defined (__ghs__)
/* Green Hills support for PowerPC */

#include <ppc_ghs.h>

static tlsf_always_inline int tlsf_ffs(unsigned int word)
{
  const unsigned int reverse = word & (~word + 1);
  const int bit = 32 - __CLZ32(reverse);
  return bit - 1;
}

static tlsf_always_inline int tlsf_fls(unsigned int word)
{
  const int bit = word ? 32 - __CLZ32(word) : 0;
  return bit - 1;
}

#else
/* Fall back to generic implementation. */

static tlsf_alwasy_inline int tlsf_fls_generic(unsigned int word)
{
  int bit = 32;

  if (!word) bit -= 1;
  if (!(word & 0xffff0000)) { word <<= 16; bit -= 16; }
  if (!(word & 0xff000000)) { word <<=  8; bit -=  8; }
  if (!(word & 0xf0000000)) { word <<=  4; bit -=  4; }
  if (!(word & 0xc0000000)) { word <<=  2; bit -=  2; }
  if (!(word & 0x80000000)) { word <<=  1; bit -=  1; }

  return bit;
}

/* Implement ffs in terms of fls. */
static tlsf_always_inline int tlsf_ffs(unsigned int word)
{
  return tlsf_fls_generic(word & (~word + 1)) - 1;
}

static tlsf_always_inline int tlsf_fls(unsigned int word)
{
  return tlsf_fls_generic(word) - 1;
}

#endif

#endif // TLSF_BITS_H
