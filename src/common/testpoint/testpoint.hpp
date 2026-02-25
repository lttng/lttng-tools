/*
 * SPDX-FileCopyrightText: 2012 Christian Babeux <christian.babeux@efficios.com>
 * SPDX-FileCopyrightText: 2026 Olivier Dion <odion@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

/*
 * TESTPOINT() creates an assembler label that can be used as a breakpoint
 * target by an external debugger.
 *
 * Unlike the dynamic testpoint() mechanism below which uses dlsym() lookups,
 * this creates assembler labels that are always emitted regardless of
 * optimization level or inlining. This makes them reliable targets for GDB
 * breakpoints even when the containing function is inlined.
 *
 * The `label` argument must be a string literal, as it is concatenated into
 * the inline assembly template at preprocessing time.
 *
 * Example: TESTPOINT("ust_app_release");
 */
#ifndef TESTPOINT
#define TESTPOINT(label)                                                 \
	__asm__ volatile(".local lttng_tools_testpoint_" label ".%=\n\t" \
			 "lttng_tools_testpoint_" label ".%= =."         \
			 :                                               \
			 :                                               \
			 :)
#endif

#ifdef NTESTPOINT

#define testpoint(name)
#define TESTPOINT_DECL(name)

#else /* NTESTPOINT */

#include <urcu.h> /* for caa_likely/unlikely */

extern int lttng_testpoint_activated;

void *lttng_testpoint_lookup(const char *name);

/*
 * Testpoint is only active if the global lttng_testpoint_activated flag is
 * set.
 * Return a non-zero error code to indicate failure.
 */
#define testpoint(name) \
	((caa_unlikely(lttng_testpoint_activated)) ? __testpoint_##name##_wrapper() : 0)

/*
 * One wrapper per testpoint is generated. This is to keep track of the symbol
 * lookup status and the corresponding function pointer, if any.
 */
#define _TESTPOINT_DECL(_name)                                                        \
	static inline int __testpoint_##_name##_wrapper(void)                         \
	{                                                                             \
		int ret = 0;                                                          \
		static int (*tp)(void);                                               \
		static int found;                                                     \
		const char *tp_name = "__testpoint_" #_name;                          \
                                                                                      \
		if (tp) {                                                             \
			ret = tp();                                                   \
		} else {                                                              \
			if (!found) {                                                 \
				tp = (int (*)(void)) lttng_testpoint_lookup(tp_name); \
				if (tp) {                                             \
					found = 1;                                    \
					ret = tp();                                   \
				} else {                                              \
					found = -1;                                   \
				}                                                     \
			}                                                             \
		}                                                                     \
		return ret;                                                           \
	}

/* Testpoint declaration */
#define TESTPOINT_DECL(name) _TESTPOINT_DECL(name)

#endif /* NTESTPOINT */
