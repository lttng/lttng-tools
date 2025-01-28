/*
 * SPDX-FileCopyrightText: 2013 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE

#include "lttng-sessiond.hpp"
#include "notification-thread-commands.hpp"
#include "ust-app.hpp"
#include "ust-registry-session-pid.hpp"
#include "ust-registry-session-uid.hpp"
#include "ust-registry.hpp"
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
 * Destroy event function call of the call RCU.
 */
static void ust_registry_event_destroy_rcu(struct rcu_head *head)
{
	DIAGNOSTIC_PUSH
	DIAGNOSTIC_IGNORE_INVALID_OFFSETOF
	lttng::sessiond::ust::registry_event *event =
		lttng::utils::container_of(head, &lttng::sessiond::ust::registry_event::_head);
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
	iter.iter.node = &event->_node;
	ret = lttng_ht_del(chan->_events, &iter);
	LTTNG_ASSERT(!ret);

	call_rcu(&event->_head, ust_registry_event_destroy_rcu);

	return;
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
		return new lsu::registry_session_per_uid(abi,
							 major,
							 minor,
							 root_shm_path,
							 shm_path,
							 euid,
							 egid,
							 tracing_id,
							 tracing_uid);
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
		return new lsu::registry_session_per_pid(
			*app, abi, major, minor, root_shm_path, shm_path, euid, egid, tracing_id);
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

lsu::registry_enum::registry_enum(std::string in_name,
				  enum lst::integer_type::signedness in_signedness) :
	name{ std::move(in_name) }, signedness{ in_signedness }
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
