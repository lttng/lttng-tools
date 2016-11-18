/*
 * Copyright (C) 2011 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _KERN_MODULES_H
#define _KERN_MODULES_H

/*
 * Compatible lttng-modules version.
 */
#define KERN_MODULES_PRE_MAJOR     1
#define KERN_MODULES_PRE_MINOR     9

#define KERN_MODULES_MAJOR         2
#define KERN_MODULES_MINOR         0

struct kern_modules_param {
	char *name;
	bool loaded;
};

#endif /* _KERN_MODULES_H */
