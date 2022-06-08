/*
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE

#include "ust-registry.hpp"
#include "lttng-sessiond.hpp"
#include "notification-thread-commands.hpp"
#include "ust-app.hpp"
#include "ust-registry-session-pid.hpp"
#include "ust-registry-session-uid.hpp"
#include "utils.hpp"

#include <common/common.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/hashtable/utils.hpp>
#include <common/make-unique-wrapper.hpp>
#include <lttng/lttng.h>

#include <inttypes.h>

namespace ls = lttng::sessiond;
namespace lst = lttng::sessiond::trace;
namespace lsu = lttng::sessiond::ust;

/*
 * Hash table match function for enumerations in the session. Match is
 * performed on enumeration name, and confirmed by comparing the enum
 * entries.
 */
static int ht_match_enum(struct cds_lfht_node *node, const void *_key)
{
	lsu::registry_enum *_enum;
	const lsu::registry_enum *key;

	LTTNG_ASSERT(node);
	LTTNG_ASSERT(_key);

	DIAGNOSTIC_PUSH
	DIAGNOSTIC_IGNORE_INVALID_OFFSETOF
	_enum = caa_container_of(node, lsu::registry_enum,
			node.node);
	DIAGNOSTIC_POP

	LTTNG_ASSERT(_enum);
	key = (lsu::registry_enum *) _key;

	return *_enum == *key;
}

/*
 * Hash table match function for enumerations in the session. Match is
 * performed by enumeration ID.
 */
static int ht_match_enum_id(struct cds_lfht_node *node, const void *_key)
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
static unsigned long ht_hash_enum(void *_key, unsigned long seed)
{
	lsu::registry_enum *key = (lsu::registry_enum *) _key;

	LTTNG_ASSERT(key);
	return hash_key_str(key->name.c_str(), seed);
}

/*
 * Destroy event function call of the call RCU.
 */
static void ust_registry_event_destroy_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_u64 *node = caa_container_of(head, struct lttng_ht_node_u64, head);
	DIAGNOSTIC_PUSH
	DIAGNOSTIC_IGNORE_INVALID_OFFSETOF
	lttng::sessiond::ust::registry_event *event =
			caa_container_of(node, lttng::sessiond::ust::registry_event, _node);
	DIAGNOSTIC_POP

	lttng::sessiond::ust::registry_event_destroy(event);
}

/*
 * For a given event in a registry, delete the entry and destroy the event.
 * This MUST be called within a RCU read side lock section.
 */
void ust_registry_channel_destroy_event(lsu::registry_channel *chan,
		lttng::sessiond::ust::registry_event *event)
{
	int ret;
	struct lttng_ht_iter iter;

	LTTNG_ASSERT(chan);
	LTTNG_ASSERT(event);
	ASSERT_RCU_READ_LOCKED();

	/* Delete the node first. */
	iter.iter.node = &event->_node.node;
	ret = lttng_ht_del(chan->_events, &iter);
	LTTNG_ASSERT(!ret);

	call_rcu(&event->_node.head, ust_registry_event_destroy_rcu);

	return;
}

static void destroy_enum(lsu::registry_enum *reg_enum)
{
	if (!reg_enum) {
		return;
	}

	delete reg_enum;
}

static void destroy_enum_rcu(struct rcu_head *head)
{
	DIAGNOSTIC_PUSH
	DIAGNOSTIC_IGNORE_INVALID_OFFSETOF
	lsu::registry_enum *reg_enum =
		caa_container_of(head, lsu::registry_enum, rcu_head);
	DIAGNOSTIC_POP

	destroy_enum(reg_enum);
}

/*
 * Lookup enumeration by name and comparing enumeration entries.
 * Needs to be called from RCU read-side critical section.
 */
static lsu::registry_enum *ust_registry_lookup_enum(
		lsu::registry_session *session,
		const lsu::registry_enum *reg_enum_lookup)
{
	lsu::registry_enum *reg_enum = NULL;
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;

	ASSERT_RCU_READ_LOCKED();

	cds_lfht_lookup(session->_enums->ht,
			ht_hash_enum((void *) reg_enum_lookup, lttng_ht_seed),
			ht_match_enum, reg_enum_lookup, &iter.iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (!node) {
	        goto end;
	}

	DIAGNOSTIC_PUSH
	DIAGNOSTIC_IGNORE_INVALID_OFFSETOF
	reg_enum = caa_container_of(node, lsu::registry_enum, node);
	DIAGNOSTIC_POP

end:
	return reg_enum;
}

/*
 * Lookup enumeration by enum ID.
 */
lsu::registry_enum::const_rcu_protected_reference
ust_registry_lookup_enum_by_id(const lsu::registry_session *session,
		const char *enum_name, uint64_t enum_id)
{
	lsu::registry_enum *reg_enum = NULL;
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
	cds_lfht_lookup(session->_enums->ht,
			ht_hash_enum((void *) &reg_enum_lookup, lttng_ht_seed),
			ht_match_enum_id, &reg_enum_lookup, &iter.iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (!node) {
		LTTNG_THROW_PROTOCOL_ERROR(fmt::format(
				"Unknown enumeration referenced by application event field: enum name = `{}`, enum id = {}",
				enum_name, enum_id));
	}

	DIAGNOSTIC_PUSH
	DIAGNOSTIC_IGNORE_INVALID_OFFSETOF
	reg_enum = caa_container_of(node, lsu::registry_enum, node);
	DIAGNOSTIC_POP

	return lsu::registry_enum::const_rcu_protected_reference{*reg_enum, std::move(rcu_lock)};
}

/*
 * Create a lsu::registry_enum from the given parameters and add it to the
 * registry hash table, or find it if already there.
 *
 * On success, return 0 else a negative value.
 *
 * Should be called with session registry mutex held.
 *
 * We receive ownership of entries.
 */
int ust_registry_create_or_find_enum(lsu::registry_session *session,
		int session_objd, char *enum_name,
		struct lttng_ust_ctl_enum_entry *raw_entries, size_t nr_entries,
		uint64_t *enum_id)
{
	int ret = 0;
	struct cds_lfht_node *nodep;
	lsu::registry_enum *reg_enum = NULL, *old_reg_enum;
	auto entries = lttng::make_unique_wrapper<lttng_ust_ctl_enum_entry, lttng::free>(raw_entries);

	LTTNG_ASSERT(session);
	LTTNG_ASSERT(enum_name);

	rcu_read_lock();

	/*
	 * This should not happen but since it comes from the UST tracer, an
	 * external party, don't assert and simply validate values.
	 */
	if (session_objd < 0 || nr_entries == 0 ||
			lttng_strnlen(enum_name, LTTNG_UST_ABI_SYM_NAME_LEN) ==
					LTTNG_UST_ABI_SYM_NAME_LEN) {
		ret = -EINVAL;
		goto end;
	}

	try {
		if (entries->start.signedness) {
			reg_enum = new lsu::registry_signed_enum(
					enum_name, entries.get(), nr_entries);
		} else {
			reg_enum = new lsu::registry_unsigned_enum(
					enum_name, entries.get(), nr_entries);
		}
	} catch (const std::exception& ex) {
		ERR("Failed to create ust registry enumeration: %s", ex.what());
		ret = -ENOMEM;
		goto end;
	}

	old_reg_enum = ust_registry_lookup_enum(session, reg_enum);
	if (old_reg_enum) {
		DBG("enum %s already in sess_objd: %u", enum_name, session_objd);
		/* Fall through. Use prior enum. */
		destroy_enum(reg_enum);
		reg_enum = old_reg_enum;
	} else {
		DBG("UST registry creating enum: %s, sess_objd: %u",
				enum_name, session_objd);
		if (session->_next_enum_id == -1ULL) {
			ret = -EOVERFLOW;
			destroy_enum(reg_enum);
			goto end;
		}
		reg_enum->id = session->_next_enum_id++;
		nodep = cds_lfht_add_unique(session->_enums->ht,
				ht_hash_enum(reg_enum, lttng_ht_seed),
				ht_match_enum_id, reg_enum,
				&reg_enum->node.node);
		LTTNG_ASSERT(nodep == &reg_enum->node.node);
	}
	DBG("UST registry reply with enum %s with id %" PRIu64 " in sess_objd: %u",
			enum_name, reg_enum->id, session_objd);
	*enum_id = reg_enum->id;
end:
	rcu_read_unlock();
	return ret;
}

/*
 * For a given enumeration in a registry, delete the entry and destroy
 * the enumeration.
 * This MUST be called within a RCU read side lock section.
 */
void ust_registry_destroy_enum(lsu::registry_session *reg_session,
		lsu::registry_enum *reg_enum)
{
	int ret;
	struct lttng_ht_iter iter;

	LTTNG_ASSERT(reg_session);
	LTTNG_ASSERT(reg_enum);
	ASSERT_RCU_READ_LOCKED();

	/* Delete the node first. */
	iter.iter.node = &reg_enum->node.node;
	ret = lttng_ht_del(reg_session->_enums.get(), &iter);
	LTTNG_ASSERT(!ret);
	call_rcu(&reg_enum->rcu_head, destroy_enum_rcu);
}

lsu::registry_session *ust_registry_session_per_uid_create(const lttng::sessiond::trace::abi& abi,
		uint32_t major,
		uint32_t minor,
		const char *root_shm_path,
		const char *shm_path,
		uid_t euid,
		gid_t egid,
		uint64_t tracing_id,
		uid_t tracing_uid)
{
	try {
		return new lsu::registry_session_per_uid(abi, major, minor, root_shm_path, shm_path,
				euid, egid, tracing_id, tracing_uid);
	} catch (const std::exception& ex) {
		ERR("Failed to create per-uid registry session: %s", ex.what());
		return nullptr;
	}
}

lsu::registry_session *ust_registry_session_per_pid_create(struct ust_app *app,
		const lttng::sessiond::trace::abi& abi,
		uint32_t major,
		uint32_t minor,
		const char *root_shm_path,
		const char *shm_path,
		uid_t euid,
		gid_t egid,
		uint64_t tracing_id)
{
	try {
		return new lsu::registry_session_per_pid(*app, abi, major, minor, root_shm_path,
				shm_path, euid, egid, tracing_id);
	} catch (const std::exception& ex) {
		ERR("Failed to create per-pid registry session: %s", ex.what());
		return nullptr;
	}
}

/*
 * Destroy session registry. This does NOT free the given pointer since it
 * might get passed as a reference. The registry lock should NOT be acquired.
 */
void ust_registry_session_destroy(lsu::registry_session *reg)
{
	delete reg;
}

lsu::registry_enum::registry_enum(
		std::string in_name, enum lst::integer_type::signedness in_signedness) :
	name{std::move(in_name)}, signedness{in_signedness}
{
	cds_lfht_node_init(&this->node.node);
	this->rcu_head = {};
}

bool lsu::operator==(const lsu::registry_enum& lhs, const lsu::registry_enum& rhs) noexcept
{
	if (lhs.signedness != rhs.signedness) {
		return false;
	}

	return lhs._is_equal(rhs);
}
