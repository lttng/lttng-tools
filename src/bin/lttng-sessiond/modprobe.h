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

#ifndef _MODPROBE_H
#define _MODPROBE_H

void modprobe_remove_lttng_all(void);
void modprobe_remove_lttng_control(void);
void modprobe_remove_lttng_data(void);
int modprobe_lttng_all(void);
int modprobe_lttng_control(void);
int modprobe_lttng_data(void);

#endif /* _MODPROBE_H */
