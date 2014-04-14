/*
 * Copyright (C)  2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _ERROR_H
#define _ERROR_H

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifndef _GNU_SOURCE
#error "lttng-tools error.h needs _GNU_SOURCE"
#endif

#include <lttng/lttng-error.h>
#include <common/compat/tid.h>

/* Stringify the expansion of a define */
#define XSTR(d) STR(d)
#define STR(s) #s

extern int lttng_opt_quiet;
extern int lttng_opt_verbose;
extern int lttng_opt_mi;

/* Error type. */
#define PRINT_ERR   0x1
#define PRINT_WARN  0x2
#define PRINT_BUG   0x3
#define PRINT_MSG   0x4
#define PRINT_DBG   0x10
#define PRINT_DBG2  0x20
#define PRINT_DBG3  0x30

/*
 * Macro for printing message depending on command line option and verbosity.
 *
 * Machine interface:
 * We use lttng_opt_mi to suppress all normal msg to stdout. We don't
 * want any nested msg to show up when printing mi to stdout(if it's the case).
 * All warnings and errors should be printed to stderr as normal.
 */
#define __lttng_print(type, fmt, args...)                           \
	do {                                                            \
		if (lttng_opt_quiet == 0 && lttng_opt_mi == 0 &&            \
				type == PRINT_MSG) {                                \
			fprintf(stdout, fmt, ## args);                          \
		} else if (lttng_opt_quiet == 0 && lttng_opt_mi == 0 &&     \
				(((type & PRINT_DBG) && lttng_opt_verbose == 1) ||  \
				((type & (PRINT_DBG | PRINT_DBG2)) &&               \
					lttng_opt_verbose == 2) ||                      \
				((type & (PRINT_DBG | PRINT_DBG2 | PRINT_DBG3)) &&  \
					lttng_opt_verbose == 3))) {                     \
			fprintf(stderr, fmt, ## args);                          \
		} else if (lttng_opt_quiet == 0 && (type & (PRINT_WARN))) { \
			fprintf(stderr, fmt, ## args);                          \
		} else if (type & (PRINT_ERR | PRINT_BUG)) {                \
			fprintf(stderr, fmt, ## args);                          \
		}                                                           \
	} while (0);

/* Three level of debug. Use -v, -vv or -vvv for the levels */
#define _ERRMSG(msg, type, fmt, args...) __lttng_print(type, msg \
		" [%ld/%ld]: " fmt " (in %s() at " __FILE__ ":" XSTR(__LINE__) ")\n", \
			(long) getpid(), (long) gettid(), ## args, __func__)

#define MSG(fmt, args...) \
	__lttng_print(PRINT_MSG, fmt "\n", ## args)
#define _MSG(fmt, args...) \
	__lttng_print(PRINT_MSG, fmt, ## args)
#define ERR(fmt, args...) \
	__lttng_print(PRINT_ERR, "Error: " fmt "\n", ## args)
#define WARN(fmt, args...) \
	__lttng_print(PRINT_WARN, "Warning: " fmt "\n", ## args)

#define BUG(fmt, args...) _ERRMSG("BUG", PRINT_BUG, fmt, ## args)

#define DBG(fmt, args...) _ERRMSG("DEBUG1", PRINT_DBG, fmt, ## args)
#define DBG2(fmt, args...) _ERRMSG("DEBUG2", PRINT_DBG2, fmt, ## args)
#define DBG3(fmt, args...) _ERRMSG("DEBUG3", PRINT_DBG3, fmt, ## args)

#define _PERROR(fmt, args...) _ERRMSG("PERROR", PRINT_ERR, fmt, ## args)

#if !defined(__linux__) || ((_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !defined(_GNU_SOURCE))

/*
 * Version using XSI strerror_r.
 */
#define PERROR(call, args...) \
	do { \
		char buf[200]; \
		strerror_r(errno, buf, sizeof(buf)); \
		_PERROR(call ": %s", ## args, buf); \
	} while(0);
#else
/*
 * Version using GNU strerror_r, for linux with appropriate defines.
 */
#define PERROR(call, args...) \
	do { \
		char *buf; \
		char tmp[200]; \
		buf = strerror_r(errno, tmp, sizeof(tmp)); \
		_PERROR(call ": %s", ## args, buf); \
	} while(0);
#endif

const char *error_get_str(int32_t code);

#endif /* _ERROR_H */
