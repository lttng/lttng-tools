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

#include <stddef.h>
#include <unistd.h>

#include "defaults.h"
#include "macros.h"

size_t default_channel_subbuf_size;
size_t default_metadata_subbuf_size;
size_t default_kernel_channel_subbuf_size;
size_t default_ust_channel_subbuf_size;

static void __attribute__((constructor)) init_defaults(void)
{
	/*
	 * The libringbuffer won't accept subbuf sizes smaller than the page size.
	 * If the default subbuf size is smaller, replace it by the page size.
	 */
	long page_size = sysconf(_SC_PAGESIZE);

	if (page_size < 0) {
		page_size = 0;
	}

	default_channel_subbuf_size =
		max(DEFAULT_CHANNEL_SUBBUF_SIZE, page_size);
	default_metadata_subbuf_size =
		max(DEFAULT_METADATA_SUBBUF_SIZE, page_size);
	default_kernel_channel_subbuf_size =
		max(DEFAULT_KERNEL_CHANNEL_SUBBUF_SIZE, page_size);
	default_ust_channel_subbuf_size =
		max(DEFAULT_UST_CHANNEL_SUBBUF_SIZE, page_size);
}
