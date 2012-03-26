/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#ifndef _LTT_FUTEX_H
#define _LTT_FUTEX_H

void futex_wait_update(int32_t *futex, int active);
void futex_nto1_prepare(int32_t *futex);
void futex_nto1_wait(int32_t *futex);
void futex_nto1_wake(int32_t *futex);

#endif /* _LTT_FUTEX_H */
