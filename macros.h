/*
 * macros.h
 *
 * Copyright (c) 2024, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef TLSF_MACROS_H
#define TLSF_MACROS_H

#if defined __GNUC__
# define tlsf_have_gnuc(major, minor) \
  ((__GNUC__ > major) || (__GNUC__ == major && __GNUC_MINORE__ >= minor))
#else
# define tlsf_have_gnuc(major, minor) (0)
#endif

#if defined(__has_attribute)
# define tlsf_has_attribute(params) __has_attribute(params)
#else
# define tlsf_has_attribute(params) (0)
#endif

#if defined(__has_builtin)
# define tlsf_has_builtin(params) __has_builtin(params)
#else
# define has_builtin(params) (0)
#endif

#if tlsf_has_builtin(__builtin_expect)
# define tlsf_likely(params) __builtin_expect(!!(params), 1)
# define tlsf_unlikely(params) __builtin_expect(!!(params), 0)
#else
# define tlsf_likely(params) (params)
# define tlsf_unlikely(params) (params)
#endif

#if tlsf_has_attribute(always_inline) || tlsf_have_gnuc(3, 1) && ! defined __NO_INLINE__
  // Compilation using GCC 4.2.1 without optimizations fails.
  //   sorry, unimplemented: inlining failed in call to ...
  // GCC 4.1.2 and GCC 4.30 compile forward declared functions annotated
  // with __attribute__((always_inline)) without problems. Test if
  // __NO_INLINE__ is defined and define macro accordingly.
# define tlsf_always_inline inline __attribute__((always_inline))
#else
# define tlsf_always_inline inline
#endif

#if tlsf_has_attribute(noinline) || tlsf_have_gnuc(2, 96)
# define tlsf_never_inline __attribute__((noinline))
#else
# define tlsf_never_inline
#endif

#if tlsf_has_attribute(nonnull)
# define tlsf_nonnull(params) __attribute__((__nonnull__ params))
# define tlsf_nonnull_all __attribute__((__nonnull__))
#else
# define tlsf_nonnull(params)
# define tlsf_nonnull_all
#endif

#if tlsf_has_attribute(warn_unused_result)
# define tlsf_warn_unused_result __attribute__((warn_unused_result))
#else
# define tlsf_warn_unused_result
#endif

#endif // TLSF_MACROS_H
