/*
 * Copyright (C) 2018 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdio.h>
#include <common/compat/uuid.h>
#include <string.h>
#include <stddef.h>

static const lttng_uuid nil_uuid;

void lttng_uuid_to_str(const lttng_uuid uuid, char *uuid_str)
{
	sprintf(uuid_str,
			"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			uuid[0], uuid[1], uuid[2], uuid[3],
			uuid[4], uuid[5], uuid[6], uuid[7],
			uuid[8], uuid[9], uuid[10], uuid[11],
			uuid[12], uuid[13], uuid[14], uuid[15]);
}

bool lttng_uuid_is_equal(const lttng_uuid a, const lttng_uuid b)
{
	return memcmp(a, b, (sizeof(lttng_uuid))) == 0;
}

bool lttng_uuid_is_nil(const lttng_uuid uuid)
{
	return memcmp(nil_uuid, uuid, sizeof(lttng_uuid)) == 0;
}
