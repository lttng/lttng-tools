/*
 * Copyright (C) 2018 - Francis Deslauriers francis.deslauriers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef LTTNG_UST_FIELD_UTILS_H
#define LTTNG_UST_FIELD_UTILS_H

#include "ust-ctl.h"

/*
 * Compare two UST fields.
 * Return 1 if both fields have identical definition, 0 otherwise.
 */
int match_ustctl_field(struct ustctl_field *first, struct ustctl_field *second);

#endif /* LTTNG_UST_FIELD_UTILS_H */
