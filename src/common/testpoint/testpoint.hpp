/*
 * Copyright (C) 2012 Christian Babeux <christian.babeux@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

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
