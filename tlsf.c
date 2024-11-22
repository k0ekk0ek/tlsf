/*
 * tlsf.c -- Two Level Segregated Fit memory allocator
 *
 * Copyright (c) 2024, NLnet Labs
 * Copyright (c) 2006-2026, Matthew Conte
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#include "tlsf.h"
#include "bits.h"

//
// Detect whether or not we are building for a 32- or 64-bit (LP/LLP)
// architecture. There is no reliable portable method at compile-time.
//
#if defined (__alpha__) || defined (__ia64__) || defined (__x86_64__) \
      || defined (_WIN64) || defined (__LP64__) || defined (__LLP64__)
#define TLSF_64BIT
#endif

// Possibly 64-bit version of tlsf_fls.
#if defined (TLSF_64BIT)
static tlsf_always_inline int tlsf_fls_sizet(size_t size)
{
  int high = (int)(size >> 32);
  int bits = 0;
  if (high)
  {
    bits = 32 + tlsf_fls(high);
  }
  else
  {
    bits = tlsf_fls((int)size & 0xffffffff);
  }

  return bits;
}
#else
#define tlsf_fls_sizet tlsf_fls
#endif

//
// Constants.
//

// Public constants: may be modified.
// log2 of number of linear subdivisions of block sizes. Larger
// values require more memory in the control structure. Values of
// 4 or 5 are typical.
#define SL_INDEX_COUNT_LOG2 (5)

// Private constants: do not modify.
#if defined (TLSF_64BIT)
  // All allocation sizes and addresses are aligned to 8 bytes.
# define ALIGN_SIZE_LOG2 (3)
#else
  // All allocation sizes and addresses are aligned to 4 bytes.
#define ALIGN_SIZE_LOG2 (2)
#endif
#define ALIGN_SIZE (1 << ALIGN_SIZE_LOG2)

  //
  // We support allocations of sizes up to (1 << FL_INDEX_MAX) bits.
  // However, because we linearly subdivide the second-level lists, and
  // our minimum size granularity is 4 bytes, it doesn't make sense to
  // create first-level lists for sizes smaller than SL_INDEX_COUNT * 4,
  // or (1 << (SL_INDEX_COUNT_LOG2 + 2)) bytes, as there we will be
  // trying to split size ranges into more slots than we have available.
  // Instead, we calculate the minimum threshold size, and place all
  // blocks below that size into the 0th first-level list.
  //

#if defined (TLSF_64BIT)
  //
  // TODO: We can increase this to support larger sizes, at the expense
  // of more overhead in the TLSF structure.
  //
#define FL_INDEX_MAX (32)
#else
#define FL_INDEX_MAX (30)
#endif
#define SL_INDEX_COUNT (1 << SL_INDEX_COUNT_LOG2)
#define FL_INDEX_SHIFT (SL_INDEX_COUNT_LOG2 + ALIGN_SIZE_LOG2)
#define FL_INDEX_COUNT (FL_INDEX_MAX - FL_INDEX_SHIFT + 1)

#define SMALL_BLOCK_SIZE (1 << FL_INDEX_SHIFT)

#define PAGE_SIZE (4096ull)
#define PAGE_MASK (~(PAGE_SIZE - 1))

//
// Cast and min/max macros.
//

#define tlsf_min(a, b)     ((a) < (b) ? (a) : (b))
#define tlsf_max(a, b)     ((a) > (b) ? (a) : (b))

//
// Static assertion mechanism.
//

#define _tlsf_glue2(x, y) x ## y
#define _tlsf_glue(x, y) _tlsf_glue2(x, y)
#define tlsf_static_assert(exp) \
  typedef char _tlsf_glue(static_assert, __LINE__)[(exp) ? 1 : -1]

// This code has been tested on 32- and 64-bit (LP/LLP) architectures.
tlsf_static_assert(sizeof(int) * CHAR_BIT == 32);
tlsf_static_assert(sizeof(size_t) * CHAR_BIT >= 32);
tlsf_static_assert(sizeof(size_t) * CHAR_BIT <= 64);

// SL_INDEX_COUNT must be <= number of bits in sl_bitmap's storage type.
tlsf_static_assert(sizeof(unsigned int) * CHAR_BIT >= SL_INDEX_COUNT);

// Ensure we've properly tuned our sizes.
tlsf_static_assert(ALIGN_SIZE == SMALL_BLOCK_SIZE / SL_INDEX_COUNT);

//
// Data structures and associated constants.
//

//
// Block header structure.
//
// There are several implementation subtleties involved:
// - The prev_phys_block field is only valid if the previous block is free.
// - The prev_phys_block field is actually stored at the end of the
//   previous block. It appears at the beginning of this structure only to
//   simplify the implementation.
// - The next_free / prev_free fields are only valid if the block is free.
//
typedef struct block_header block_header_t;
struct block_header {
  // Points to the previous physical block.
  uintptr_t prev_phys_block;

  // Size of this block, excluding block header.
  size_t size;

  // Next and previous free blocks.
  uintptr_t next_free;
  uintptr_t prev_free;
};

//
// Since block sizes are always at least a multiple of 4, the two least
// significant bits of the size field are used to store the block status:
// - bit 0: whether block is busy or free
// - bit 1: whether previous block is busy or free
//
static const size_t block_header_free_bit = 1 << 0;
static const size_t block_header_prev_free_bit = 1 << 1;

//
// The size of the block header exposed to used blocks is the size field.
// The prev_phys_block field is stored *inside* the previous free block.
//
static const size_t block_header_overhead = sizeof(size_t);

// User data starts directly after the size field in a used block.
static const size_t block_start_offset =
  offsetof(block_header_t, size) + sizeof(size_t);

//
// A free block must be large enough to store its header minus the size of
// the prev_phys_block field, and no larger than the number of addressable
// bits for FL_INDEX.
//
static const size_t block_size_min =
  sizeof(block_header_t) - sizeof(block_header_t *);
static const size_t block_size_max = (size_t)(1llu << FL_INDEX_MAX);



// TLSF control structure.
typedef struct tlsf tlsf_t;
struct tlsf {
  // Empty lists point at this block to indicate they are free.
  block_header_t block_null;

  // Bitmaps for free lits.
  uint32_t fl_bitmap;
  uint32_t sl_bitmap[FL_INDEX_COUNT];

  // Head of free lists.
  uintptr_t blocks[FL_INDEX_COUNT][SL_INDEX_COUNT];

  size_t size;
};


tlsf_nonnull((1))
static tlsf_always_inline block_header_t *block_header(
  const tlsf_t *tlsf, uintptr_t block)
{
  return (block_header_t*)((uintptr_t)tlsf + block);
}

tlsf_nonnull_all
static tlsf_always_inline size_t block_size(
  const tlsf_t *tlsf, uintptr_t block)
{
  const block_header_t *header = block_header(tlsf, block);
  return header->size & ~(block_header_free_bit | block_header_prev_free_bit);
}

tlsf_nonnull((1))
static tlsf_always_inline void block_set_size(
  const tlsf_t *tlsf, uintptr_t block, size_t size)
{
  block_header_t *header = block_header(tlsf, block);
  const size_t bits =
    header->size & (block_header_free_bit | block_header_prev_free_bit);
  header->size = size | bits;
}

tlsf_nonnull((1))
static tlsf_always_inline bool block_is_last(
  const tlsf_t *tlsf, uintptr_t block)
{
  return 0 == block_size(tlsf, block);
}

tlsf_nonnull((1))
static tlsf_always_inline bool block_is_free(
  const tlsf_t *tlsf, uintptr_t block)
{
  const block_header_t *header = block_header(tlsf, block);
  return (header->size & block_header_free_bit) != 0;
}

tlsf_nonnull((1))
static tlsf_always_inline void block_set_free(
  const tlsf_t *tlsf, uintptr_t block)
{
  block_header_t *header = block_header(tlsf, block);
  header->size |= block_header_free_bit;
}

tlsf_nonnull((1))
static tlsf_always_inline void block_set_used(
  const tlsf_t *tlsf, uintptr_t block)
{
  block_header_t *header = block_header(tlsf, block);
  header->size &= ~block_header_free_bit;
}

tlsf_nonnull((1))
static tlsf_always_inline bool block_is_prev_free(
  const tlsf_t *tlsf, uintptr_t block)
{
  const block_header_t *header = block_header(tlsf, block);
  return (header->size & block_header_prev_free_bit) != 0;
}

tlsf_nonnull((1))
static tlsf_always_inline void block_set_prev_free(
  const tlsf_t *tlsf, uintptr_t block)
{
  block_header_t *header = block_header(tlsf, block);
  header->size |= block_header_prev_free_bit;
}

tlsf_nonnull((1))
static tlsf_always_inline void block_set_prev_used(
  const tlsf_t *tlsf, uintptr_t block)
{
  block_header_t *header = block_header(tlsf, block);
  header->size &= ~block_header_prev_free_bit;
}

// Return location of previous block.
tlsf_nonnull((1))
static tlsf_always_inline uintptr_t block_prev(
  const tlsf_t *tlsf, uintptr_t block)
{
  assert(block_is_prev_free(tlsf, block) && "previous block must be free");
  const block_header_t *header = block_header(tlsf, block);
  return header->prev_phys_block;
}

// Return location of next block.
tlsf_nonnull((1))
static tlsf_always_inline uintptr_t block_next(
  const tlsf_t *tlsf, uintptr_t block)
{
  size_t size = block_size(tlsf, block);
  return block + (size - block_header_overhead);
}

// Link a new block with its physical neighbor.
tlsf_nonnull((1))
static tlsf_always_inline void block_link_next(
  const tlsf_t *tlsf, uintptr_t block)
{
  uintptr_t next = block_next(tlsf, block);
  block_header_t *header = block_header(tlsf, next);
  header->prev_phys_block = block;
}

tlsf_nonnull((1))
static tlsf_always_inline void block_mark_as_free(
  const tlsf_t *tlsf, uintptr_t block)
{
  uintptr_t next = block_next(tlsf, block);
  block_set_prev_free(tlsf, next);
  block_set_free(tlsf, block);
}

tlsf_nonnull((1))
static tlsf_always_inline void block_mark_as_used(
  const tlsf_t *tlsf, uintptr_t block)
{
  uintptr_t next = block_next(tlsf, block);
  block_set_prev_used(tlsf, next);
  block_set_used(tlsf, block);
}

static tlsf_always_inline size_t align_up(size_t x, size_t align)
{
  assert(0 == (align & (align - 1)) && "must align to a power of two");
  return (x + (align - 1)) & ~(align - 1);
}

static tlsf_always_inline size_t align_down(size_t x, size_t align)
{
  assert(0 == (align & (align - 1)) && "must align to a power of two");
  return x - (x & (align - 1));
}

//
// Adjust an allocation size to be aligned to word size, and no smaller
// than internal minimum.
//
static tlsf_always_inline size_t adjust_request_size(
  size_t size, size_t align)
{
  assert(size);
  const size_t aligned = align_up(size, align);
  // Aligned sized must not exceed block_size_max or we'll go out of bounds
  // on sl_bitmap.
  if (tlsf_unlikely(aligned >= block_size_max))
    return 0;
  return tlsf_max(aligned, block_size_min);
}

//
// TLSF utility functions. In most cases, these are direct translations of
// the documentation found in the white paper.
//

static tlsf_always_inline void mapping_insert(
  size_t size, int32_t *fli, int32_t *sli)
{
  int32_t fl, sl;
  if (size < SMALL_BLOCK_SIZE) {
    // Store small blocks in first list.
    fl = 0;
    sl = (int)size / (SMALL_BLOCK_SIZE / SL_INDEX_COUNT);
  } else {
    fl = tlsf_fls_sizet(size);
    sl = (int)(size >> (fl - SL_INDEX_COUNT_LOG2)) ^ (1 << SL_INDEX_COUNT_LOG2);
    fl -= (FL_INDEX_SHIFT - 1);
  }
  *fli = fl;
  *sli = sl;
}

// This version rounds up to the next block size (for allocations)
static tlsf_always_inline void mapping_search(
  size_t size, int32_t *fli, int32_t *sli)
{
  if (size >= SMALL_BLOCK_SIZE) {
    const size_t round = (1 << (tlsf_fls_sizet(size) - SL_INDEX_COUNT_LOG2)) - 1;
    size += round;
  }
  mapping_insert(size, fli, sli);
}

tlsf_nonnull_all
static tlsf_always_inline uintptr_t search_suitable_block(
  tlsf_t *tlsf, int32_t *fli, int32_t *sli)
{
  int32_t fl = *fli, sl = *sli;

  // First, search for a block in the list associated with the given
  // fl/sl index.
  uint32_t sl_map = tlsf->sl_bitmap[fl] & (~0u << sl);
  if (!sl_map) {
    // No block exists. Search the next largest first-level list.
    const uint32_t fl_map = tlsf->fl_bitmap & (~0u << (fl + 1));
    if (!fl_map)
      return 0;
    fl = tlsf_ffs(fl_map);
    *fli = fl;
    sl_map = tlsf->sl_bitmap[fl];
  }
  assert(sl_map && "internal error - second level bitmap is null");
  sl = tlsf_ffs(sl_map);
  *sli = sl;

  // Return first block in the free list.
  return tlsf->blocks[fl][sl];
}

// Remove a free block from the free list.
tlsf_nonnull((1))
static tlsf_always_inline void remove_free_block(
  tlsf_t *tlsf, uintptr_t block, int32_t fl, int32_t sl)
{
  block_header_t *header = block_header(tlsf, block);
  block_header_t *prev = block_header(tlsf, header->prev_free);
  block_header_t *next = block_header(tlsf, header->next_free);

  assert(prev && "prev_free field can not be null");
  assert(next && "next_free field can not be null");
  next->prev_free = header->prev_free;
  prev->next_free = header->next_free;

  // If this block is the head of the free list, set new head.
  if (tlsf->blocks[fl][sl] == block) {
    tlsf->blocks[fl][sl] = header->next_free;
    // If the new head is null, clear the bitmap.
    if (header->next_free == 0) {
      tlsf->sl_bitmap[fl] &= ~(1u << sl);
      // If the second bitmap is now empty, clear the fl bitmap.
      if (!tlsf->sl_bitmap[fl])
        tlsf->fl_bitmap &= ~(1u << fl);
    }
  }
}

// Insert a free block into the free list.
tlsf_nonnull((1))
static tlsf_always_inline void insert_free_block(
  tlsf_t *tlsf, uintptr_t block, int32_t fl, int32_t sl)
{
  block_header_t *header = block_header(tlsf, block);
  block_header_t *current = block_header(tlsf, tlsf->blocks[fl][sl]);

  assert(header && "cannot insert a null entry into the free list");
  assert(current && "free list cannot have a null entry");
  header->next_free = tlsf->blocks[fl][sl];
  header->prev_free = 0;
  current->prev_free = block;

#if 0
  assert(block_to_object(block) == align_ptr(block_to_object(block), ALIGN_SIZE)
    && "block not aligned properly");
#endif
  // Insert the new block at the head of the list, and mark the first- and
  // second-level bitmaps appropriately.
  tlsf->blocks[fl][sl] = block;
  tlsf->fl_bitmap |= (1u << fl);
  tlsf->sl_bitmap[fl] |= (1u << sl);
}

// Remove a given block from the free list.
tlsf_nonnull((1))
static tlsf_always_inline void block_remove(
  tlsf_t *tlsf, uintptr_t block)
{
  int32_t fl, sl;
  mapping_insert(block_size(tlsf, block), &fl, &sl);
  remove_free_block(tlsf, block, fl, sl);
}

// Inseret a given block into the free list.
tlsf_nonnull((1))
static tlsf_always_inline void block_insert(
  tlsf_t *tlsf, uintptr_t block)
{
  int32_t fl, sl;
  mapping_insert(block_size(tlsf, block), &fl, &sl);
  insert_free_block(tlsf, block, fl, sl);
}

tlsf_nonnull((1))
static tlsf_always_inline bool block_can_split(
  const tlsf_t *tlsf, uintptr_t block, size_t size)
{
  const block_header_t *header = block_header(tlsf, block);
  return header->size >= sizeof(block_header_t) + size;
}

tlsf_nonnull((1))
static tlsf_always_inline uintptr_t block_split(
  tlsf_t *tlsf, uintptr_t block, size_t size)
{
  uintptr_t next_phys_block =
    (block + block_start_offset) + (size - block_header_overhead);
  const size_t next_phys_block_size =
    block_size(tlsf, block) - (size + block_header_overhead);

#if 0
  assert(block_to_ptr(remaining) == align_ptr(block_to_ptr(remaining), ALIGN_SIZE)
    && "remaining block not aligned properly");
#endif

  block_set_size(tlsf, next_phys_block, next_phys_block_size);
  block_link_next(tlsf, next_phys_block);
  block_set_size(tlsf, block, size);
  block_link_next(tlsf, block);
  block_mark_as_free(tlsf, next_phys_block);
  block_insert(tlsf, next_phys_block);
  return next_phys_block;
}

// Merge a free block's storage into an adjacent free block.
tlsf_nonnull((1))
static tlsf_always_inline uintptr_t block_merge(
  tlsf_t *tlsf, uintptr_t block, uintptr_t next)
{
  assert(!block_is_last(tlsf, block) && "previous block can't be last");
  block_header_t *header = block_header(tlsf, block);
  // Note: Leaves flags untouched.
  header->size += block_size(tlsf, next) + block_header_overhead;
  block_link_next(tlsf, block);
  return block;
}

// Merge a just-freed block with an adjacent previous free block.
tlsf_nonnull((1))
static tlsf_always_inline uintptr_t block_merge_prev(
  tlsf_t *tlsf, uintptr_t block)
{
  if (!block_is_prev_free(tlsf, block))
    return block;
  uintptr_t prev = block_prev(tlsf, block);
  assert(prev && "previous physical block can't be null");
  assert(block_is_free(tlsf, prev) && "previous block is not free though marked as such");
  block_remove(tlsf, prev);
  return block_merge(tlsf, prev, block);
}

// Merge a just-freed block with an adjacent free block.
tlsf_nonnull((1))
static tlsf_always_inline uintptr_t block_merge_next(
  tlsf_t *tlsf, uintptr_t block)
{
  uintptr_t next = block_next(tlsf, block);
  if (!block_is_free(tlsf, next))
    return block;
  assert(!block_is_last(tlsf, next) && "previous block can't be last");
  block_remove(tlsf, next);
  return block_merge(tlsf, block, next);
}

// Trim any trailing block space off the end of a block, return to pool.
tlsf_nonnull((1))
static tlsf_always_inline void block_trim_free(
  tlsf_t *tlsf, uintptr_t block, size_t size)
{
  assert(block_is_free(tlsf, block) && "block must be free");
  if (block_can_split(tlsf, block, size)) {
    uintptr_t next = block_split(tlsf, block, size);
    block_set_prev_free(tlsf, next);
  }
}

tlsf_nonnull((1))
static tlsf_always_inline uintptr_t block_locate_free(
  tlsf_t *tlsf, size_t size)
{
  int32_t fl = 0, sl = 0;
  uintptr_t block = 0;

  assert(size);

  mapping_search(size, &fl, &sl);
  // mapping_search can futz with the size, so for excessively large sizes it
  // can sometimes wind up with indices that are off the end of the block
  // array. So, we protect against that here, since this is the only callsite
  // of mapping_search. Note that we don't need to check sl, since it comes
  // from a modulo operation that guarantees it's always in range.
  if (fl < FL_INDEX_COUNT)
    block = search_suitable_block(tlsf, &fl, &sl);

  if (tlsf_unlikely(!block))
    return 0;
  assert(block_size(tlsf, block) >= size);
  remove_free_block(tlsf, block, fl, sl);
  return block;
}

tlsf_nonnull((1))
static tlsf_always_inline uintptr_t block_prepare_used(
  tlsf_t *tlsf, uintptr_t block, size_t size)
{
  if (tlsf_unlikely(!block))
    return 0;
  assert(size && "size must be non-zero");
  block_trim_free(tlsf, block, size);
  block_mark_as_used(tlsf, block);
  return block + block_start_offset;
}

size_t tlsf_block_size(const tlsf_t *tlsf, uintptr_t object)
{
  if (tlsf_unlikely(object <= sizeof(tlsf_t)))
    return 0;
  uintptr_t block = object - block_start_offset;
  return block_size(tlsf, block);
}

//
// Size of the TLSF structures in a given memory block passed to
// tlsf_create, equal to the size of a control_t
//
size_t tlsf_size(void)
{
  return sizeof(tlsf_t);
}

size_t tlsf_align_size(void)
{
  return ALIGN_SIZE;
}

size_t tlsf_block_size_min(void)
{
  return block_size_min;
}

size_t tlsf_block_size_max(void)
{
  return block_size_max;
}

//
// Overhead of the TLSF structures in a given memory block passed to
// tlsf_add_pool, equal to the overhead of a free block and the
// sentinel block.
//
size_t tlsf_pool_overhead(void)
{
  return 2 * block_header_overhead;
}

size_t tlsf_alloc_overhead(void)
{
  return block_header_overhead;
}


//
// TLSF main interface.
//

tlsf_t *tlsf_init(void *mem, size_t size)
{
  // Address must be page aligned.
  if (((uintptr_t)mem & PAGE_MASK) != (uintptr_t)mem)
    return NULL;
  // Size must be a multiple of page size.
  // FIXME: May not make sense anymore(?)
  if ((size & PAGE_MASK) != size || size / PAGE_SIZE == 0)
    return NULL;

  const size_t overhead = sizeof(tlsf_t) + tlsf_pool_overhead();
  const size_t pool_bytes = align_down(size - overhead, ALIGN_SIZE);

  // FIXME: Support larger pool sizes via multiple blocks of block_size_max(?)
  if (pool_bytes < block_size_min || pool_bytes > block_size_max)
    return NULL;

  tlsf_t *tlsf = mem;

  // Clear structure and point all empty lists at the null block.
  tlsf->block_null.next_free = 0;
  tlsf->block_null.prev_free = 0;
  tlsf->fl_bitmap = 0;
  for (uint32_t i = 0; i < FL_INDEX_COUNT; ++i) {
    tlsf->sl_bitmap[i] = 0;
    for (uint32_t j = 0; j < SL_INDEX_COUNT; ++j) {
      tlsf->blocks[i][j] = 0;
    }
  }

  tlsf->size = size;

  // Create the main free block. Offset the start of the block slightly
  // so that the prev_phys_block field falls outside the pool - it will
  // never be used.
  uintptr_t block = size - (pool_bytes + block_header_overhead);
  block_set_size(tlsf, block, pool_bytes);
  block_set_free(tlsf, block);
  block_set_prev_used(tlsf, block);
  block_insert(tlsf, block);

  // Split the block to create a zero-size sentinel block.
  block_link_next(tlsf, block);
  block = block_next(tlsf, block);
  block_set_size(tlsf, block, 0);
  block_set_used(tlsf, block);
  block_set_prev_free(tlsf, block);

  return tlsf;
}

uintptr_t tlsf_malloc(tlsf_t *tlsf, size_t size)
{
  assert(tlsf);

  if (tlsf_unlikely(!size))
    return 0;
  const size_t adjust = adjust_request_size(size, ALIGN_SIZE);
  uintptr_t block = block_locate_free(tlsf, adjust);
  return block_prepare_used(tlsf, block, adjust);
}

void tlsf_free(tlsf_t *tlsf, uintptr_t object)
{
  assert(tlsf);

  // Don't attempt to free a NULL pointer.
  if (tlsf_unlikely(object <= block_start_offset))
    return;
  uintptr_t block = object - block_start_offset;
  assert(!block_is_free(tlsf, block) && "block already marked as free");
  block_mark_as_free(tlsf, block);
  block = block_merge_prev(tlsf, block);
  block = block_merge_next(tlsf, block);
  block_insert(tlsf, block);
}
