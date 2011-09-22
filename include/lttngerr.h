/*
 * Copyright (C)  2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _LTTNGERR_H
#define _LTTNGERR_H

#include <errno.h>
#include <stdio.h>

/* Stringify the expansion of a define */
#define XSTR(d) STR(d)
#define STR(s) #s

extern int opt_quiet;
extern int opt_verbose;

#define PRINT_ERR   0x1
#define PRINT_WARN  0x2
#define PRINT_BUG   0x3
#define PRINT_MSG   0x4
#define PRINT_DBG   0x10
#define PRINT_DBG2  0x20
#define PRINT_DBG3  0x30

/*
 * Macro for printing message depending on command line option and verbosity.
 */
#define __lttng_print(type, fmt, args...)                                 \
	do {                                                                  \
		if (opt_quiet == 0) {                                             \
			if (type == PRINT_MSG ||                                      \
					((type & PRINT_DBG) && opt_verbose == 1) ||           \
					((type & (PRINT_DBG | PRINT_DBG2)) &&                 \
						opt_verbose == 2) ||                              \
					((type & (PRINT_DBG | PRINT_DBG2 | PRINT_DBG3)) &&    \
						opt_verbose == 3)) {                              \
				fprintf(stdout, fmt, ## args);                            \
			} else if (type & (PRINT_ERR | PRINT_WARN | PRINT_BUG)) {     \
				fprintf(stderr, fmt, ## args);                            \
			}                                                             \
		}                                                                 \
	} while (0);

#define MSG(fmt, args...) \
	__lttng_print(PRINT_MSG, fmt "\n", ## args)
#define ERR(fmt, args...) \
	__lttng_print(PRINT_ERR, "Error: " fmt "\n", ## args)
#define WARN(fmt, args...) \
	__lttng_print(PRINT_WARN, "Warning: " fmt "\n", ## args)
#define BUG(fmt, args...) \
	__lttng_print(PRINT_BUG, "BUG: " fmt "\n", ## args)

/* Three level of debug. Use -v, -vv or -vvv for the levels */
#define DBG(fmt, args...) __lttng_print(PRINT_DBG, "DEBUG1: " fmt \
		" [in %s() at " __FILE__ ":" XSTR(__LINE__) "]\n", ## args, __func__)
#define DBG2(fmt, args...) __lttng_print(PRINT_DBG2, "DEBUG2: " fmt \
		" [in %s() at " __FILE__ ":" XSTR(__LINE__) "]\n", ## args, __func__)
#define DBG3(fmt, args...) __lttng_print(PRINT_DBG3, "DEBUG3: " fmt \
		" [in %s() at " __FILE__ ":" XSTR(__LINE__) "]\n", ## args, __func__)

#define _PERROR(fmt, args...) \
	__lttng_print(PRINT_ERR, "perror " fmt "\n", ## args)

#define PERROR(call, args...) \
    do { \
		char *buf; \
		char tmp[200]; \
		buf = strerror_r(errno, tmp, sizeof(tmp)); \
		_PERROR(call ": %s", ## args, buf); \
	} while(0);

#endif /* _LTTNGERR_H */
