/*
 * tlsf.h -- Two Level Segregated Fit memory allocator
 *
 * Copyright (c) 2006-2016, Matthew Conte
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef TLSF_H
#define TLSF_H

/*
** Two Level Segregated Fit memory allocator, version 3.1.
** Written by Matthew Conte
**	http://tlsf.baisoku.org
**
** Based on the original documentation by Miguel Masmano:
**	http://www.gii.upv.es/tlsf/main/docs
**
** This implementation was written to the specification
** of the document, therefore no GPL restrictions apply.
*/

#include <stddef.h>
#include <stdint.h>

#include "macros.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* tlsf_t: a TLSF structure. */
typedef struct tlsf tlsf_t;

#if 0
/* pool_t: a block of memory that TLSF can manage. */
typedef void* pool_t;
#endif

tlsf_nonnull((1))
tlsf_warn_unused_result
tlsf_t *tlsf_init(void *mem, size_t size);

#if 0
/* Create/destroy a memory pool. */
tlsf_t tlsf_create(void* mem);
tlsf_t tlsf_create_with_pool(void* mem, size_t bytes);
void tlsf_destroy(tlsf_t tlsf);
pool_t tlsf_get_pool(tlsf_t tlsf);

/* Add/remove memory pools. */
pool_t tlsf_add_pool(tlsf_t tlsf, void* mem, size_t bytes);
void tlsf_remove_pool(tlsf_t tlsf, pool_t pool);
#endif

tlsf_nonnull((1))
static tlsf_always_inline void *tlsf_swizzle(tlsf_t *tlsf, uintptr_t object)
{
  // extra checks in debug builds
  return (void*)((uintptr_t)tlsf + (uintptr_t)object);
}

tlsf_nonnull((1,2))
static tlsf_always_inline intptr_t tlsf_unswizzle(tlsf_t *tlsf, void *ptr)
{
  return (intptr_t)((uintptr_t)ptr - (uintptr_t)tlsf);
}

/* malloc/memalign/realloc/free replacements. */
tlsf_nonnull((1))
uintptr_t tlsf_malloc(tlsf_t *tlsf, size_t size);

#if 0
void* tlsf_memalign(tlsf_t tlsf, size_t align, size_t bytes);
void* tlsf_realloc(tlsf_t tlsf, void* ptr, size_t size);
#endif

tlsf_nonnull((1))
void tlsf_free(tlsf_t *tlsf, uintptr_t object);

/* Returns internal block size, not original request size */
tlsf_nonnull((1))
size_t tlsf_block_size(const tlsf_t *tlsf, uintptr_t object);

/* Overheads/limits of internal structures. */
size_t tlsf_size(void);
size_t tlsf_align_size(void);
size_t tlsf_block_size_min(void);
size_t tlsf_block_size_max(void);
size_t tlsf_pool_overhead(void);
size_t tlsf_alloc_overhead(void);

/* Debugging. */
#if 0
typedef void (*tlsf_walker)(void* ptr, size_t size, int used, void* user);
void tlsf_walk_pool(pool_t pool, tlsf_walker walker, void* user);
/* Returns nonzero if any internal consistency check fails. */
int tlsf_check(tlsf_t tlsf);
int tlsf_check_pool(pool_t pool);
#endif

#if defined(__cplusplus)
};
#endif

#endif
