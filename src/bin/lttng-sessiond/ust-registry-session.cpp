/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "ust-registry.hpp"

#include <common/compat/directory-handle.hpp>
#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/macros.hpp>
#include <common/pthread-lock.hpp>
#include <common/runas.hpp>

#include <fcntl.h>
#include <sstream>
#include <string>

ust_registry_session::ust_registry_session(uint32_t bits_per_long,
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
		uint64_t tracing_id) :
	_bits_per_long{bits_per_long},
	_uint8_t_alignment{uint8_t_alignment},
	_uint16_t_alignment{uint16_t_alignment},
	_uint32_t_alignment{uint32_t_alignment},
	_uint64_t_alignment{uint64_t_alignment},
	_long_alignment{long_alignment},
	_byte_order{byte_order},
	_uid{euid},
	_gid{egid},
	_app_tracer_version_major{major},
	_app_tracer_version_minor{minor},
	_tracing_id{tracing_id}
{
	pthread_mutex_init(&_lock, NULL);
	strncpy(_root_shm_path, root_shm_path, sizeof(_root_shm_path));
	_root_shm_path[sizeof(_root_shm_path) - 1] = '\0';
	if (shm_path[0]) {
		strncpy(_shm_path, shm_path, sizeof(_shm_path));
		_shm_path[sizeof(_shm_path) - 1] = '\0';
		strncpy(_metadata_path, shm_path, sizeof(_metadata_path));
		_metadata_path[sizeof(_metadata_path) - 1] = '\0';
		strncat(_metadata_path, "/metadata",
				sizeof(_metadata_path) - strlen(_metadata_path) - 1);
	}

	if (_shm_path[0]) {
		if (run_as_mkdir_recursive(_shm_path, S_IRWXU | S_IRWXG, euid, egid)) {
			LTTNG_THROW_POSIX("run_as_mkdir_recursive", errno);
		}
	}

	if (_metadata_path[0]) {
		/* Create metadata file. */
		const int ret = run_as_open(_metadata_path, O_WRONLY | O_CREAT | O_EXCL,
				S_IRUSR | S_IWUSR, euid, egid);

		if (ret < 0) {
			std::stringstream ss;

			ss << "Opening metadata file '" << _metadata_path << "'";
			LTTNG_THROW_POSIX(ss.str(), errno);
		}

		_metadata_fd = ret;
	}

	_enums.reset(lttng_ht_new(0, LTTNG_HT_TYPE_STRING));
	if (!_enums) {
		LTTNG_THROW_POSIX("Failed to create enums hash table", ENOMEM);
	}

	/* hash/match functions are specified at call site. */
	_enums->match_fct = NULL;
	_enums->hash_fct = NULL;

	_channels.reset(lttng_ht_new(0, LTTNG_HT_TYPE_U64));
	if (!_channels) {
		LTTNG_THROW_POSIX("Failed to create channels hash table", ENOMEM);
	}

	if (lttng_uuid_generate(_uuid)) {
		LTTNG_THROW_POSIX("Failed to generate UST uuid", errno);
	}
}

ust_registry_session::~ust_registry_session()
{
	int ret;
	struct lttng_ht_iter iter;
	struct ust_registry_channel *chan;
	struct ust_registry_enum *reg_enum;

	/* On error, EBUSY can be returned if lock. Code flow error. */
	ret = pthread_mutex_destroy(&_lock);
	LTTNG_ASSERT(!ret);

	if (_channels) {
		rcu_read_lock();
		/* Destroy all event associated with this registry. */
		cds_lfht_for_each_entry (_channels->ht, &iter.iter, chan, node.node) {
			/* Delete the node from the ht and free it. */
			ret = lttng_ht_del(_channels.get(), &iter);
			LTTNG_ASSERT(!ret);
			ust_registry_channel_destroy(chan, true);
		}

		rcu_read_unlock();
	}

	free(_metadata);
	if (_metadata_fd >= 0) {
		ret = close(_metadata_fd);
		if (ret) {
			PERROR("close");
		}

		ret = run_as_unlink(_metadata_path, _uid, _gid);
		if (ret) {
			PERROR("unlink");
		}
	}

	if (_root_shm_path[0]) {
		/* Try to delete the directory hierarchy. */
		(void) run_as_rmdir_recursive(_root_shm_path, _uid, _gid,
				LTTNG_DIRECTORY_HANDLE_SKIP_NON_EMPTY_FLAG);
	}

	/* Destroy the enum hash table */
	if (_enums) {
		rcu_read_lock();
		/* Destroy all enum entries associated with this registry. */
		cds_lfht_for_each_entry (_enums->ht, &iter.iter, reg_enum, node.node) {
			ust_registry_destroy_enum(this, reg_enum);
		}

		rcu_read_unlock();
	}
}

void ust_registry_session::statedump()
{
	lttng::pthread::lock_guard registry_lock(_lock);

	const int ret = ust_metadata_session_statedump(this);
	if (ret) {
		LTTNG_THROW_ERROR(
				"Failed to generate session metadata during registry session creation");
	}
}
