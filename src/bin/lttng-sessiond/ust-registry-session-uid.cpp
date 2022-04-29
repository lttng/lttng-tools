/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "ust-registry.hpp"

ust_registry_session_per_uid::ust_registry_session_per_uid(uint32_t bits_per_long,
		uint32_t uint8_t_alignment,
		uint32_t uint16_t_alignment,
		uint32_t uint32_t_alignment,
		uint32_t uint64_t_alignment,
		uint32_t long_alignment,
		int byte_order,
		uint32_t major,
		uint32_t minor,
		const char *root_shm_path,
		const char *shm_path,
		uid_t euid,
		gid_t egid,
		uint64_t tracing_id,
		uid_t tracing_uid) :
	ust_registry_session{bits_per_long, uint8_t_alignment, uint16_t_alignment,
			uint32_t_alignment, uint64_t_alignment, long_alignment, byte_order, major,
			minor, root_shm_path, shm_path, euid, egid, tracing_id},
	_tracing_uid{tracing_uid}
{
	statedump();
}

lttng_buffer_type ust_registry_session_per_uid::get_buffering_scheme() const noexcept
{
	return LTTNG_BUFFER_PER_UID;
}
