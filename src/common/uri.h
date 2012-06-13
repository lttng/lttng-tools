/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
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

#ifndef _LTT_URI_H
#define _LTT_URI_H

#include <lttng/lttng.h>

int uri_compare(struct lttng_uri *uri1, struct lttng_uri *uri2);
void uri_free(struct lttng_uri *uri);
ssize_t uri_parse(const char *str_uri, struct lttng_uri **uris);

#endif /* _LTT_URI_H */
