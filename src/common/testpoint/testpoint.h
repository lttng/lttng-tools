/*
 * Copyright (C) 2012 - Christian Babeux <christian.babeux@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
#define testpoint(name)				\
	((caa_unlikely(lttng_testpoint_activated))	\
	? __testpoint_##name##_wrapper() : 0)

/*
 * One wrapper per testpoint is generated. This is to keep track of the symbol
 * lookup status and the corresponding function pointer, if any.
 */
#define _TESTPOINT_DECL(_name)						\
	static inline int __testpoint_##_name##_wrapper(void)		\
	{								\
		int ret = 0;						\
		static int (*tp)(void);					\
		static int found;					\
		const char *tp_name = "__testpoint_" #_name;		\
									\
		if (tp) {						\
			ret = tp();					\
		} else {						\
			if (!found) {					\
				tp = lttng_testpoint_lookup(tp_name);	\
				if (tp) {				\
					found = 1;			\
					ret = tp();			\
				} else {				\
					found = -1;			\
				}					\
			}						\
		}							\
		return ret;						\
	}

/* Testpoint declaration */
#define TESTPOINT_DECL(name)	\
	_TESTPOINT_DECL(name)

#endif /* NTESTPOINT */
