/* Copyright (C)  2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 * 
 */

#ifndef _LTTNGERR_H
#define _LTTNGERR_H

#include <errno.h>
#include <stdarg.h>

extern int opt_quiet;
extern int opt_verbose;

enum __lttng_print_type {
	PRINT_ERR,
	PRINT_WARN,
	PRINT_BUG,
	PRINT_DBG,
	PRINT_MSG,
};

/*
 *  __lttng_print
 *
 *  Internal function for printing message
 *  depending on command line option and verbosity.
 */
void __lttng_print(enum __lttng_print_type type, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	if (opt_quiet == 0) {
		if (type == PRINT_MSG || (opt_verbose && type == PRINT_DBG)) {
			vfprintf(stdout, fmt, ap);
		} else if (type != PRINT_MSG && type != PRINT_DBG) {
			vfprintf(stderr, fmt, ap);
		}
	}

	va_end(ap);
}

#define MSG(fmt, args...) __lttng_print(PRINT_MSG, fmt "\n", ## args)
#define ERR(fmt, args...) __lttng_print(PRINT_ERR, "Error: " fmt "\n", ## args)
#define WARN(fmt, args...) __lttng_print(PRINT_WARN, "Warning: " fmt "\n", ## args)
#define BUG(fmt, args...) __lttng_print(PRINT_BUG, "BUG: " fmt "\n", ## args)
#define DBG(fmt, args...) __lttng_print(PRINT_DBG, "DEBUG: " fmt "\n", ## args)

#endif /* _LTTNGERR_H */
