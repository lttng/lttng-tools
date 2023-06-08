/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "ctf2-trace-class-visitor.hpp"
#include "field.hpp"
#include "lttng-sessiond.hpp"
#include "notification-thread-commands.hpp"
#include "session.hpp"
#include "trace-class.hpp"
#include "tsdl-trace-class-visitor.hpp"
#include "ust-app.hpp"
#include "ust-field-convert.hpp"
#include "ust-registry.hpp"

#include <common/compat/directory-handle.hpp>
#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/hashtable/utils.hpp>
#include <common/macros.hpp>
#include <common/make-unique.hpp>
#include <common/pthread-lock.hpp>
#include <common/runas.hpp>
#include <common/time.hpp>
#include <common/urcu.hpp>

#include <fcntl.h>
#include <functional>
#include <initializer_list>
#include <mutex>
#include <sstream>
#include <string>

namespace ls = lttng::sessiond;
namespace lst = lttng::sessiond::trace;
namespace lsu = lttng::sessiond::ust;

namespace {
lttng_uuid generate_uuid_or_throw()
{
	lttng_uuid new_uuid;

	if (lttng_uuid_generate(new_uuid)) {
		LTTNG_THROW_POSIX("Failed to generate UST uuid", errno);
	}

	return new_uuid;
}

int get_count_order(unsigned int count)
{
	int order;

	order = lttng_fls(count) - 1;
	if (count & (count - 1)) {
		order++;
	}

	LTTNG_ASSERT(order >= 0);
	return order;
}

void clear_metadata_file(int fd)
{
	const auto lseek_ret = lseek(fd, 0, SEEK_SET);
	if (lseek_ret < 0) {
		LTTNG_THROW_POSIX(
			"Failed to seek to the beginning of the metadata file while clearing it",
			errno);
	}

	const auto ret = ftruncate(fd, 0);
	if (ret < 0) {
		LTTNG_THROW_POSIX("Failed to truncate the metadata file while clearing it", errno);
	}
}

/*
 * Validate that the id has reached the maximum allowed or not.
 */
bool is_max_channel_id(uint32_t id)
{
	return id == UINT32_MAX;
}

void destroy_channel_rcu(struct rcu_head *head)
{
	DIAGNOSTIC_PUSH
	DIAGNOSTIC_IGNORE_INVALID_OFFSETOF
	lsu::registry_channel *chan =
		lttng::utils::container_of(head, &lsu::registry_channel::_rcu_head);
	DIAGNOSTIC_POP

	delete chan;
}

/*
 * Destroy every element of the registry and free the memory. This does NOT
 * free the registry pointer since it might not have been allocated before so
 * it's the caller responsability.
 *
 * Called from ~registry_session(), must not throw.
 */
void destroy_channel(lsu::registry_channel *chan, bool notify) noexcept
{
	struct lttng_ht_iter iter;
	lttng::sessiond::ust::registry_event *event;
	enum lttng_error_code cmd_ret;

	LTTNG_ASSERT(chan);

	if (notify) {
		cmd_ret = notification_thread_command_remove_channel(
			the_notification_thread_handle, chan->_consumer_key, LTTNG_DOMAIN_UST);
		if (cmd_ret != LTTNG_OK) {
			ERR("Failed to remove channel from notification thread");
		}
	}

	if (chan->_events) {
		lttng::urcu::read_lock_guard read_lock_guard;

		/* Destroy all event associated with this registry. */
		DIAGNOSTIC_PUSH
		DIAGNOSTIC_IGNORE_INVALID_OFFSETOF
		cds_lfht_for_each_entry (chan->_events->ht, &iter.iter, event, _node) {
			/* Delete the node from the ht and free it. */
			ust_registry_channel_destroy_event(chan, event);
		}
		DIAGNOSTIC_POP
	}

	call_rcu(&chan->_rcu_head, destroy_channel_rcu);
}

void destroy_enum(lsu::registry_enum *reg_enum)
{
	if (!reg_enum) {
		return;
	}

	delete reg_enum;
}

void destroy_enum_rcu(struct rcu_head *head)
{
	DIAGNOSTIC_PUSH
	DIAGNOSTIC_IGNORE_INVALID_OFFSETOF
	lsu::registry_enum *reg_enum =
		lttng::utils::container_of(head, &lsu::registry_enum::rcu_head);
	DIAGNOSTIC_POP

	destroy_enum(reg_enum);
}

/*
 * Hash table match function for enumerations in the session. Match is
 * performed on enumeration name, and confirmed by comparing the enum
 * entries.
 */
int ht_match_enum(struct cds_lfht_node *node, const void *_key)
{
	lsu::registry_enum *_enum;
	const lsu::registry_enum *key;

	LTTNG_ASSERT(node);
	LTTNG_ASSERT(_key);

	DIAGNOSTIC_PUSH
	DIAGNOSTIC_IGNORE_INVALID_OFFSETOF
	_enum = caa_container_of(node, lsu::registry_enum, node.node);
	DIAGNOSTIC_POP

	LTTNG_ASSERT(_enum);
	key = (lsu::registry_enum *) _key;

	return *_enum == *key;
}

/*
 * Hash table match function for enumerations in the session. Match is
 * performed by enumeration ID.
 */
int ht_match_enum_id(struct cds_lfht_node *node, const void *_key)
{
	lsu::registry_enum *_enum;
	const lsu::registry_enum *key = (lsu::registry_enum *) _key;

	LTTNG_ASSERT(node);
	LTTNG_ASSERT(_key);

	DIAGNOSTIC_PUSH
	DIAGNOSTIC_IGNORE_INVALID_OFFSETOF
	_enum = caa_container_of(node, lsu::registry_enum, node.node);
	DIAGNOSTIC_POP

	LTTNG_ASSERT(_enum);

	if (_enum->id != key->id) {
		goto no_match;
	}

	/* Match. */
	return 1;

no_match:
	return 0;
}

/*
 * Hash table hash function for enumerations in the session. The
 * enumeration name is used for hashing.
 */
unsigned long ht_hash_enum(void *_key, unsigned long seed)
{
	lsu::registry_enum *key = (lsu::registry_enum *) _key;

	LTTNG_ASSERT(key);
	return hash_key_str(key->name.c_str(), seed);
}
} /* namespace */

void lsu::details::locked_registry_session_release(lsu::registry_session *session)
{
	pthread_mutex_unlock(&session->_lock);
}

lsu::registry_session::registry_session(const struct lst::abi& in_abi,
					uint32_t major,
					uint32_t minor,
					const char *root_shm_path,
					const char *shm_path,
					uid_t euid,
					gid_t egid,
					uint64_t tracing_id) :
	lst::trace_class(in_abi, generate_uuid_or_throw()),
	_root_shm_path{ root_shm_path ? root_shm_path : "" },
	_shm_path{ shm_path ? shm_path : "" },
	_metadata_path{ _shm_path.size() > 0 ? lttng::format("{}/metadata", _shm_path) :
					       std::string("") },
	_uid{ euid },
	_gid{ egid },
	_app_tracer_version{ .major = major, .minor = minor },
	_tracing_id{ tracing_id },
	_clock{ lttng::make_unique<lsu::clock_class>() },
	_metadata_generating_visitor{ lttng::make_unique<ls::tsdl::trace_class_visitor>(
		abi,
		[this](const std::string& fragment) { _append_metadata_fragment(fragment); }) },
	_packet_header{ _create_packet_header() }
{
	pthread_mutex_init(&_lock, nullptr);
	if (_shm_path.size() > 0) {
		if (run_as_mkdir_recursive(_shm_path.c_str(), S_IRWXU | S_IRWXG, euid, egid)) {
			LTTNG_THROW_POSIX("run_as_mkdir_recursive", errno);
		}
	}

	if (_metadata_path.size() > 0) {
		/* Create metadata file. */
		const int ret = run_as_open(_metadata_path.c_str(),
					    O_WRONLY | O_CREAT | O_EXCL,
					    S_IRUSR | S_IWUSR,
					    euid,
					    egid);
		if (ret < 0) {
			LTTNG_THROW_POSIX(
				lttng::format(
					"Failed to open metadata file during registry session creation: path = {}",
					_metadata_path),
				errno);
		}

		_metadata_fd = ret;
	}

	_enums.reset(lttng_ht_new(0, LTTNG_HT_TYPE_STRING));
	if (!_enums) {
		LTTNG_THROW_POSIX("Failed to create enums hash table", ENOMEM);
	}

	/* hash/match functions are specified at call site. */
	_enums->match_fct = nullptr;
	_enums->hash_fct = nullptr;

	_channels.reset(lttng_ht_new(0, LTTNG_HT_TYPE_U64));
	if (!_channels) {
		LTTNG_THROW_POSIX("Failed to create channels hash table", ENOMEM);
	}
}

lst::type::cuptr lsu::registry_session::_create_packet_header() const
{
	lst::structure_type::fields packet_header_fields;

	/* uint32_t magic */
	packet_header_fields.emplace_back(lttng::make_unique<lst::field>(
		"magic",
		lttng::make_unique<lst::integer_type>(
			abi.uint32_t_alignment,
			abi.byte_order,
			32,
			lst::integer_type::signedness::UNSIGNED,
			lst::integer_type::base::HEXADECIMAL,
			std::initializer_list<lst::integer_type::role>(
				{ lst::integer_type::role::PACKET_MAGIC_NUMBER }))));

	/* uuid */
	packet_header_fields.emplace_back(lttng::make_unique<lst::field>(
		"uuid",
		lttng::make_unique<lst::static_length_blob_type>(
			0,
			16,
			std::initializer_list<lst::static_length_blob_type::role>(
				{ lst::static_length_blob_type::role::METADATA_STREAM_UUID }))));

	/* uint32_t stream_id */
	packet_header_fields.emplace_back(lttng::make_unique<lst::field>(
		"stream_id",
		lttng::make_unique<lst::integer_type>(
			abi.uint32_t_alignment,
			abi.byte_order,
			32,
			lst::integer_type::signedness::UNSIGNED,
			lst::integer_type::base::DECIMAL,
			std::initializer_list<lst::integer_type::role>(
				{ lst::integer_type::role::DATA_STREAM_CLASS_ID }))));

	/* uint64_t stream_instance_id */
	packet_header_fields.emplace_back(lttng::make_unique<lst::field>(
		"stream_instance_id",
		lttng::make_unique<lst::integer_type>(
			abi.uint64_t_alignment,
			abi.byte_order,
			64,
			lst::integer_type::signedness::UNSIGNED,
			lst::integer_type::base::DECIMAL,
			std::initializer_list<lst::integer_type::role>(
				{ lst::integer_type::role::DATA_STREAM_ID }))));

	return lttng::make_unique<lst::structure_type>(0, std::move(packet_header_fields));
}

const lst::type *lsu::registry_session::packet_header() const noexcept
{
	return _packet_header.get();
}

/*
 * For a given enumeration in a registry, delete the entry and destroy
 * the enumeration.
 *
 * Note that this is used by ~registry_session() and must not throw.
 */
void lsu::registry_session::_destroy_enum(lsu::registry_enum *reg_enum) noexcept
{
	int ret;
	lttng::urcu::read_lock_guard read_lock_guard;

	LTTNG_ASSERT(reg_enum);
	ASSERT_RCU_READ_LOCKED();

	/* Delete the node first. */
	struct lttng_ht_iter iter;
	iter.iter.node = &reg_enum->node.node;
	ret = lttng_ht_del(_enums.get(), &iter);
	LTTNG_ASSERT(!ret);
	call_rcu(&reg_enum->rcu_head, destroy_enum_rcu);
}

lsu::registry_session::~registry_session()
{
	int ret;
	struct lttng_ht_iter iter;
	lsu::registry_channel *chan;
	lsu::registry_enum *reg_enum;

	/* On error, EBUSY can be returned if lock. Code flow error. */
	ret = pthread_mutex_destroy(&_lock);
	LTTNG_ASSERT(!ret);

	if (_channels) {
		lttng::urcu::read_lock_guard read_lock_guard;

		/* Destroy all event associated with this registry. */
		DIAGNOSTIC_PUSH
		DIAGNOSTIC_IGNORE_INVALID_OFFSETOF
		cds_lfht_for_each_entry (_channels->ht, &iter.iter, chan, _node.node) {
			/* Delete the node from the ht and free it. */
			ret = lttng_ht_del(_channels.get(), &iter);
			LTTNG_ASSERT(!ret);
			destroy_channel(chan, true);
		}
		DIAGNOSTIC_POP
	}

	free(_metadata);
	if (_metadata_fd >= 0) {
		ret = close(_metadata_fd);
		if (ret) {
			PERROR("close");
		}

		ret = run_as_unlink(_metadata_path.c_str(), _uid, _gid);
		if (ret) {
			PERROR("unlink");
		}
	}

	if (_root_shm_path[0]) {
		/* Try to delete the directory hierarchy. */
		(void) run_as_rmdir_recursive(_root_shm_path.c_str(),
					      _uid,
					      _gid,
					      LTTNG_DIRECTORY_HANDLE_SKIP_NON_EMPTY_FLAG);
	}

	/* Destroy the enum hash table */
	if (_enums) {
		lttng::urcu::read_lock_guard read_lock_guard;

		/* Destroy all enum entries associated with this registry. */
		DIAGNOSTIC_PUSH
		DIAGNOSTIC_IGNORE_INVALID_OFFSETOF
		cds_lfht_for_each_entry (_enums->ht, &iter.iter, reg_enum, node.node) {
			_destroy_enum(reg_enum);
		}
		DIAGNOSTIC_POP
	}
}

lsu::registry_session::locked_ptr lsu::registry_session::lock() noexcept
{
	pthread_mutex_lock(&_lock);
	return locked_ptr(this);
}

/*
 * Initialize registry with default values.
 */
void lsu::registry_session::add_channel(uint64_t key)
{
	lttng::pthread::lock_guard session_lock_guard(_lock);

	/*
	 * Assign a channel ID right now since the event notification comes
	 * *before* the channel notify so the ID needs to be set at this point so
	 * the metadata can be dumped for that event.
	 */
	if (is_max_channel_id(_used_channel_id)) {
		LTTNG_THROW_ERROR(lttng::format(
			"Failed to allocate unique id for channel under session while adding channel"));
	}

	auto chan = new lsu::registry_channel(
		_get_next_channel_id(),
		abi,
		_clock->name,
		/* Registered channel listener. */
		[this](const lsu::registry_channel& registered_channel) {
			/*
			 * Channel registration completed, serialize it's layout's
			 * description.
			 */
			registered_channel.accept(*_metadata_generating_visitor);
		},
		/* Added event listener. */
		[this](const lsu::registry_channel& channel,
		       const lsu::registry_event& added_event) {
			/*
			 * The channel and its event classes will be dumped at once when
			 * it is registered. This check prevents event classes from being
			 * declared before their stream class.
			 */
			if (channel.is_registered()) {
				added_event.accept(*_metadata_generating_visitor);
			}
		});

	lttng::urcu::read_lock_guard rcu_read_lock_guard;
	lttng_ht_node_init_u64(&chan->_node, key);
	lttng_ht_add_unique_u64(_channels.get(), &chan->_node);
}

lttng::sessiond::ust::registry_channel& lsu::registry_session::channel(uint64_t channel_key) const
{
	lttng::urcu::read_lock_guard read_lock_guard;
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;

	ASSERT_LOCKED(_lock);

	lttng_ht_lookup(_channels.get(), &channel_key, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (!node) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(lttng::format(
			"Invalid channel key provided: channel key = {}", channel_key));
	}

	DIAGNOSTIC_PUSH
	DIAGNOSTIC_IGNORE_INVALID_OFFSETOF
	auto chan = lttng::utils::container_of(node, &lsu::registry_channel::_node);
	DIAGNOSTIC_POP
	return *chan;
}

void lsu::registry_session::remove_channel(uint64_t channel_key, bool notify)
{
	struct lttng_ht_iter iter;
	int ret;
	lttng::urcu::read_lock_guard read_lock_guard;

	ASSERT_LOCKED(_lock);
	auto& channel_to_remove = channel(channel_key);

	iter.iter.node = &channel_to_remove._node.node;
	ret = lttng_ht_del(_channels.get(), &iter);
	LTTNG_ASSERT(!ret);
	destroy_channel(&channel_to_remove, notify);
}

void lsu::registry_session::accept(
	lttng::sessiond::trace::trace_class_environment_visitor& visitor) const
{
	ASSERT_LOCKED(_lock);

	visitor.visit(lst::environment_field<const char *>("domain", "ust"));
	visitor.visit(lst::environment_field<const char *>("tracer_name", "lttng-ust"));
	visitor.visit(lst::environment_field<int64_t>("tracer_major", _app_tracer_version.major));
	visitor.visit(lst::environment_field<int64_t>("tracer_minor", _app_tracer_version.minor));
	visitor.visit(lst::environment_field<const char *>(
		"tracer_buffering_scheme",
		buffering_scheme() == LTTNG_BUFFER_PER_PID ? "pid" : "uid"));
	visitor.visit(lst::environment_field<int64_t>("architecture_bit_width", abi.bits_per_long));

	{
		/* The caller already holds the session and session list locks. */
		ASSERT_SESSION_LIST_LOCKED();
		const auto session = lttng::sessiond::find_session_by_id(_tracing_id);

		LTTNG_ASSERT(session);
		ASSERT_LOCKED(session->lock);

		visitor.visit(lst::environment_field<const char *>(
			"trace_name",
			session->has_auto_generated_name ? DEFAULT_SESSION_NAME : session->name));
		visitor.visit(lst::environment_field<std::string>(
			"trace_creation_datetime",
			lttng::utils::time_to_iso8601_str(session->creation_time)));
		visitor.visit(lst::environment_field<const char *>("hostname", session->hostname));
	}
}

void lsu::registry_session::_accept_on_clock_classes(lst::trace_class_visitor& visitor) const
{
	ASSERT_LOCKED(_lock);
	_clock->accept(visitor);
}

void lsu::registry_session::_accept_on_stream_classes(lst::trace_class_visitor& visitor) const
{
	ASSERT_LOCKED(_lock);

	std::vector<const lttng::sessiond::ust::registry_channel *> sorted_stream_classes;

	{
		lttng::urcu::read_lock_guard rcu_lock_guard;
		const lsu::registry_channel *channel;
		lttng_ht_iter channel_it;

		DIAGNOSTIC_PUSH
		DIAGNOSTIC_IGNORE_INVALID_OFFSETOF
		cds_lfht_for_each_entry (_channels->ht, &channel_it.iter, channel, _node.node) {
			sorted_stream_classes.emplace_back(channel);
		}
		DIAGNOSTIC_POP
	}

	std::sort(sorted_stream_classes.begin(),
		  sorted_stream_classes.end(),
		  [](const lttng::sessiond::ust::registry_channel *a,
		     const lttng::sessiond::ust::registry_channel *b) { return a->id < b->id; });

	for (const auto stream_class : sorted_stream_classes) {
		stream_class->accept(visitor);
	}
}

/*
 * Return next available channel id and increment the used counter. The
 * is_max_channel_id function MUST be called before in order to validate
 * if the maximum number of IDs have been reached. If not, it is safe to call
 * this function.
 *
 * Return a unique channel ID. If max is reached, the used_channel_id counter
 * is returned.
 */
uint32_t lsu::registry_session::_get_next_channel_id()
{
	if (is_max_channel_id(_used_channel_id)) {
		return _used_channel_id;
	}

	_used_channel_id++;
	return _next_channel_id++;
}

void lsu::registry_session::_increase_metadata_size(size_t reservation_length)
{
	const auto new_len = _metadata_len + reservation_length;
	auto new_alloc_len = new_len;
	const auto old_alloc_len = _metadata_alloc_len;

	/* Rounding the new allocation length to the next power of 2 would overflow. */
	if (new_alloc_len > (UINT32_MAX >> 1)) {
		LTTNG_THROW_ERROR(
			"Failed to reserve trace metadata storage as the new size would overflow");
	}

	/* The current allocation length is already the largest we can afford. */
	if ((old_alloc_len << 1) > (UINT32_MAX >> 1)) {
		LTTNG_THROW_ERROR(
			"Failed to reserve trace metadata storage as the max size was already reached");
	}

	if (new_alloc_len > old_alloc_len) {
		new_alloc_len =
			std::max<size_t>(1U << get_count_order(new_alloc_len), old_alloc_len << 1);

		auto newptr = (char *) realloc(_metadata, new_alloc_len);
		if (!newptr) {
			LTTNG_THROW_POSIX("Failed to allocate trace metadata storage", errno);
		}

		_metadata = newptr;

		/* We zero directly the memory from start of allocation. */
		memset(&_metadata[old_alloc_len], 0, new_alloc_len - old_alloc_len);
		_metadata_alloc_len = new_alloc_len;
	}

	_metadata_len += reservation_length;
}

void lsu::registry_session::_append_metadata_fragment(const std::string& fragment)
{
	const auto offset = _metadata_len;

	_increase_metadata_size(fragment.size());
	memcpy(&_metadata[offset], fragment.c_str(), fragment.size());

	if (_metadata_fd >= 0) {
		const auto bytes_written =
			lttng_write(_metadata_fd, fragment.c_str(), fragment.size());

		if (bytes_written != fragment.size()) {
			LTTNG_THROW_POSIX("Failed to write trace metadata fragment to file", errno);
		}
	}
}

void lsu::registry_session::_reset_metadata()
{
	_metadata_len_sent = 0;
	memset(_metadata, 0, _metadata_alloc_len);
	_metadata_len = 0;

	if (_metadata_fd > 0) {
		/* Clear the metadata file's content. */
		clear_metadata_file(_metadata_fd);
	}
}

void lsu::registry_session::_generate_metadata()
{
	trace_class::accept(*_metadata_generating_visitor);
}

void lsu::registry_session::regenerate_metadata()
{
	lttng::pthread::lock_guard registry_lock(_lock);

	/* Resample the clock */
	_clock = lttng::make_unique<lsu::clock_class>();

	_metadata_version++;
	_reset_metadata();
	_generate_metadata();
}

/*
 * Lookup enumeration by enum ID.
 *
 * Note that there is no need to lock the registry session as this only
 * performs an RCU-protected look-up. The function also return an rcu-protected
 * reference, which ensures that the caller keeps the RCU read lock until it
 * disposes of the object.
 */
lsu::registry_enum::const_rcu_protected_reference
lsu::registry_session::enumeration(const char *enum_name, uint64_t enum_id) const
{
	lsu::registry_enum *reg_enum = nullptr;
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;
	lttng::urcu::unique_read_lock rcu_lock;
	/*
	 * Hack: only the name is used for hashing; the rest of the attributes
	 * can be fudged.
	 */
	lsu::registry_signed_enum reg_enum_lookup(enum_name, nullptr, 0);

	ASSERT_RCU_READ_LOCKED();

	reg_enum_lookup.id = enum_id;
	cds_lfht_lookup(_enums->ht,
			ht_hash_enum((void *) &reg_enum_lookup, lttng_ht_seed),
			ht_match_enum_id,
			&reg_enum_lookup,
			&iter.iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (!node) {
		LTTNG_THROW_PROTOCOL_ERROR(lttng::format(
			"Unknown enumeration referenced by application event field: enum name = `{}`, enum id = {}",
			enum_name,
			enum_id));
	}

	DIAGNOSTIC_PUSH
	DIAGNOSTIC_IGNORE_INVALID_OFFSETOF
	reg_enum = lttng::utils::container_of(node, &lsu::registry_enum::node);
	DIAGNOSTIC_POP

	return lsu::registry_enum::const_rcu_protected_reference{ *reg_enum, std::move(rcu_lock) };
}

/*
 * Lookup enumeration by name and comparing enumeration entries.
 * Needs to be called from RCU read-side critical section.
 */
lsu::registry_enum *
lsu::registry_session::_lookup_enum(const lsu::registry_enum *reg_enum_lookup) const
{
	lsu::registry_enum *reg_enum = nullptr;
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;

	ASSERT_RCU_READ_LOCKED();

	cds_lfht_lookup(_enums->ht,
			ht_hash_enum((void *) reg_enum_lookup, lttng_ht_seed),
			ht_match_enum,
			reg_enum_lookup,
			&iter.iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (!node) {
		goto end;
	}

	DIAGNOSTIC_PUSH
	DIAGNOSTIC_IGNORE_INVALID_OFFSETOF
	reg_enum = lttng::utils::container_of(node, &lsu::registry_enum::node);
	DIAGNOSTIC_POP

end:
	return reg_enum;
}

/*
 * Create a lsu::registry_enum from the given parameters and add it to the
 * registry hash table, or find it if already there.
 *
 * Should be called with session registry mutex held.
 *
 * We receive ownership of entries.
 */
void lsu::registry_session::create_or_find_enum(int session_objd,
						const char *enum_name,
						struct lttng_ust_ctl_enum_entry *raw_entries,
						size_t nr_entries,
						uint64_t *enum_id)
{
	struct cds_lfht_node *nodep;
	lsu::registry_enum *reg_enum = nullptr, *old_reg_enum;
	lttng::urcu::read_lock_guard read_lock_guard;
	auto entries =
		lttng::make_unique_wrapper<lttng_ust_ctl_enum_entry, lttng::free>(raw_entries);

	LTTNG_ASSERT(enum_name);

	/*
	 * This should not happen but since it comes from the UST tracer, an
	 * external party, don't assert and simply validate values.
	 */
	if (session_objd < 0) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(lttng::format(
			"Invalid parameters used to create or look-up enumeration from registry session: session_objd = {}",
			session_objd));
	}
	if (nr_entries == 0) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(lttng::format(
			"Invalid parameters used to create or look-up enumeration from registry session: nr_entries = {}",
			nr_entries));
	}
	if (lttng_strnlen(enum_name, LTTNG_UST_ABI_SYM_NAME_LEN) == LTTNG_UST_ABI_SYM_NAME_LEN) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(
			"Invalid parameters used to create or look-up enumeration from registry session: enumeration name is not null terminated");
	}

	if (entries->start.signedness) {
		reg_enum = new lsu::registry_signed_enum(enum_name, entries.get(), nr_entries);
	} else {
		reg_enum = new lsu::registry_unsigned_enum(enum_name, entries.get(), nr_entries);
	}

	old_reg_enum = _lookup_enum(reg_enum);
	if (old_reg_enum) {
		DBG("enum %s already in sess_objd: %u", enum_name, session_objd);
		/* Fall through. Use prior enum. */
		destroy_enum(reg_enum);
		reg_enum = old_reg_enum;
	} else {
		DBG("UST registry creating enum: %s, sess_objd: %u", enum_name, session_objd);
		if (_next_enum_id == -1ULL) {
			destroy_enum(reg_enum);
			LTTNG_THROW_ERROR(
				"Failed to allocate unique enumeration ID as it would overflow");
		}

		reg_enum->id = _next_enum_id++;
		nodep = cds_lfht_add_unique(_enums->ht,
					    ht_hash_enum(reg_enum, lttng_ht_seed),
					    ht_match_enum_id,
					    reg_enum,
					    &reg_enum->node.node);
		LTTNG_ASSERT(nodep == &reg_enum->node.node);
	}

	DBG("UST registry reply with enum %s with id %" PRIu64 " in sess_objd: %u",
	    enum_name,
	    reg_enum->id,
	    session_objd);
	*enum_id = reg_enum->id;
}
