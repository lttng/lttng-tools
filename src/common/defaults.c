/*
 * Copyright (C) 2012 - Simon Marchi <simon.marchi@polymtl.ca>
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

#define _LGPL_SOURCE
#include <stddef.h>
#include <unistd.h>

#include "defaults.h"
#include "macros.h"
#include "align.h"

static size_t default_channel_subbuf_size;
static size_t default_metadata_subbuf_size;
static size_t default_kernel_channel_subbuf_size;
static size_t default_ust_pid_channel_subbuf_size;
static size_t default_ust_uid_channel_subbuf_size;

LTTNG_HIDDEN
size_t default_get_channel_subbuf_size(void)
{
	return max(_DEFAULT_CHANNEL_SUBBUF_SIZE, PAGE_SIZE);
}

LTTNG_HIDDEN
size_t default_get_metadata_subbuf_size(void)
{
	return max(DEFAULT_METADATA_SUBBUF_SIZE, PAGE_SIZE);
}

LTTNG_HIDDEN
size_t default_get_kernel_channel_subbuf_size(void)
{
	return max(DEFAULT_KERNEL_CHANNEL_SUBBUF_SIZE, PAGE_SIZE);
}

LTTNG_HIDDEN
size_t default_get_ust_pid_channel_subbuf_size(void)
{
	return max(DEFAULT_UST_PID_CHANNEL_SUBBUF_SIZE, PAGE_SIZE);
}

LTTNG_HIDDEN
size_t default_get_ust_uid_channel_subbuf_size(void)
{
	return max(DEFAULT_UST_UID_CHANNEL_SUBBUF_SIZE, PAGE_SIZE);
}
