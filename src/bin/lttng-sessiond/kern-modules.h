/*
 * Copyright (C) 2011 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA  02111-1307, USA.
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
	const char *name;
	int required;
};

#endif /* _KERN_MODULES_H */
