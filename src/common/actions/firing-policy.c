/*
 * Copyright (C) 2021 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <common/buffer-view.h>
#include <common/dynamic-buffer.h>
#include <common/error.h>
#include <common/macros.h>
#include <common/payload-view.h>
#include <common/payload.h>
#include <limits.h>
#include <lttng/action/firing-policy-internal.h>
#include <lttng/action/firing-policy.h>
#include <stdbool.h>
#include <sys/types.h>

#define IS_EVERY_N_FIRING_POLICY(policy)         \
	(lttng_firing_policy_get_type(policy) == \
			LTTNG_FIRING_POLICY_TYPE_EVERY_N)

#define IS_ONCE_AFTER_N_FIRING_POLICY(policy)    \
	(lttng_firing_policy_get_type(policy) == \
			LTTNG_FIRING_POLICY_TYPE_ONCE_AFTER_N)

typedef void (*firing_policy_destroy_cb)(
		struct lttng_firing_policy *firing_policy);
typedef int (*firing_policy_serialize_cb)(
		struct lttng_firing_policy *firing_policy,
		struct lttng_payload *payload);
typedef bool (*firing_policy_equal_cb)(const struct lttng_firing_policy *a,
		const struct lttng_firing_policy *b);
typedef ssize_t (*firing_policy_create_from_payload_cb)(
		struct lttng_payload_view *view,
		struct lttng_firing_policy **firing_policy);
typedef struct lttng_firing_policy *(*firing_policy_copy_cb)(
		const struct lttng_firing_policy *source);

struct lttng_firing_policy {
	enum lttng_firing_policy_type type;
	firing_policy_serialize_cb serialize;
	firing_policy_equal_cb equal;
	firing_policy_destroy_cb destroy;
	firing_policy_copy_cb copy;
};

struct lttng_firing_policy_every_n {
	struct lttng_firing_policy parent;
	uint64_t interval;
};

struct lttng_firing_policy_once_after_n {
	struct lttng_firing_policy parent;
	uint64_t threshold;
};

struct lttng_firing_policy_comm {
	/* enum lttng_firing_policy_type */
	int8_t firing_policy_type;
} LTTNG_PACKED;

struct lttng_firing_policy_once_after_n_comm {
	uint64_t threshold;
} LTTNG_PACKED;

struct lttng_firing_policy_every_n_comm {
	uint64_t interval;
} LTTNG_PACKED;

/* Forward declaration. */
static void lttng_firing_policy_init(struct lttng_firing_policy *firing_policy,
		enum lttng_firing_policy_type type,
		firing_policy_serialize_cb serialize,
		firing_policy_equal_cb equal,
		firing_policy_destroy_cb destroy,
		firing_policy_copy_cb copy);

/* Forward declaration. Every n */
static bool lttng_firing_policy_every_n_should_execute(
		const struct lttng_firing_policy *policy, uint64_t counter);

/* Forward declaration. Once after N */
static bool lttng_firing_policy_once_after_n_should_execute(
		const struct lttng_firing_policy *policy, uint64_t counter);

LTTNG_HIDDEN
const char *lttng_firing_policy_type_string(
		enum lttng_firing_policy_type firing_policy_type)
{
	switch (firing_policy_type) {
	case LTTNG_FIRING_POLICY_TYPE_EVERY_N:
		return "EVERY-N";
	case LTTNG_FIRING_POLICY_TYPE_ONCE_AFTER_N:
		return "ONCE-AFTER-N";
	default:
		return "???";
	}
}

enum lttng_firing_policy_type lttng_firing_policy_get_type(
		const struct lttng_firing_policy *policy)
{
	return policy ? policy->type : LTTNG_FIRING_POLICY_TYPE_UNKNOWN;
}

LTTNG_HIDDEN
void lttng_firing_policy_init(struct lttng_firing_policy *firing_policy,
		enum lttng_firing_policy_type type,
		firing_policy_serialize_cb serialize,
		firing_policy_equal_cb equal,
		firing_policy_destroy_cb destroy,
		firing_policy_copy_cb copy)
{
	firing_policy->type = type;
	firing_policy->serialize = serialize;
	firing_policy->equal = equal;
	firing_policy->destroy = destroy;
	firing_policy->copy = copy;
}

void lttng_firing_policy_destroy(struct lttng_firing_policy *firing_policy)
{
	if (!firing_policy) {
		return;
	}

	firing_policy->destroy(firing_policy);
}

LTTNG_HIDDEN
int lttng_firing_policy_serialize(struct lttng_firing_policy *firing_policy,
		struct lttng_payload *payload)
{
	int ret;
	const struct lttng_firing_policy_comm firing_policy_comm = {
		.firing_policy_type = (int8_t) firing_policy->type,
	};

	ret = lttng_dynamic_buffer_append(&payload->buffer, &firing_policy_comm,
			sizeof(firing_policy_comm));
	if (ret) {
		goto end;
	}

	ret = firing_policy->serialize(firing_policy, payload);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

static ssize_t lttng_firing_policy_once_after_n_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_firing_policy **firing_policy)
{
	ssize_t consumed_len = -1;
	struct lttng_firing_policy *policy = NULL;
	const struct lttng_firing_policy_once_after_n_comm *comm;
	const struct lttng_payload_view comm_view =
			lttng_payload_view_from_view(view, 0, sizeof(*comm));

	if (!view || !firing_policy) {
		consumed_len = -1;
		goto end;
	}

	if (!lttng_payload_view_is_valid(&comm_view)) {
		/* Payload not large enough to contain the header. */
		consumed_len = -1;
		goto end;
	}

	comm = (const struct lttng_firing_policy_once_after_n_comm *)
			comm_view.buffer.data;

	policy = lttng_firing_policy_once_after_n_create(comm->threshold);
	if (policy == NULL) {
		consumed_len = -1;
		goto end;
	}

	*firing_policy = policy;
	consumed_len = sizeof(*comm);

end:
	return consumed_len;
}

static ssize_t lttng_firing_policy_every_n_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_firing_policy **firing_policy)
{
	ssize_t consumed_len = -1;
	struct lttng_firing_policy *policy = NULL;
	const struct lttng_firing_policy_every_n_comm *comm;
	const struct lttng_payload_view comm_view =
			lttng_payload_view_from_view(view, 0, sizeof(*comm));

	if (!view || !firing_policy) {
		consumed_len = -1;
		goto end;
	}

	if (!lttng_payload_view_is_valid(&comm_view)) {
		/* Payload not large enough to contain the header. */
		consumed_len = -1;
		goto end;
	}

	comm = (const struct lttng_firing_policy_every_n_comm *)
			comm_view.buffer.data;

	policy = lttng_firing_policy_every_n_create(comm->interval);
	if (policy == NULL) {
		consumed_len = -1;
		goto end;
	}

	*firing_policy = policy;
	consumed_len = sizeof(*comm);

end:
	return consumed_len;
}

LTTNG_HIDDEN
ssize_t lttng_firing_policy_create_from_payload(struct lttng_payload_view *view,
		struct lttng_firing_policy **firing_policy)
{
	ssize_t consumed_len, specific_firing_policy_consumed_len;
	firing_policy_create_from_payload_cb create_from_payload_cb;
	const struct lttng_firing_policy_comm *firing_policy_comm;
	const struct lttng_payload_view firing_policy_comm_view =
			lttng_payload_view_from_view(
					view, 0, sizeof(*firing_policy_comm));

	if (!view || !firing_policy) {
		consumed_len = -1;
		goto end;
	}

	if (!lttng_payload_view_is_valid(&firing_policy_comm_view)) {
		/* Payload not large enough to contain the header. */
		consumed_len = -1;
		goto end;
	}

	firing_policy_comm =
			(const struct lttng_firing_policy_comm *)
					firing_policy_comm_view.buffer.data;

	DBG("Create firing_policy from payload: firing-policy-type=%s",
			lttng_firing_policy_type_string(
					firing_policy_comm->firing_policy_type));

	switch (firing_policy_comm->firing_policy_type) {
	case LTTNG_FIRING_POLICY_TYPE_EVERY_N:
		create_from_payload_cb =
				lttng_firing_policy_every_n_create_from_payload;
		break;
	case LTTNG_FIRING_POLICY_TYPE_ONCE_AFTER_N:
		create_from_payload_cb =
				lttng_firing_policy_once_after_n_create_from_payload;
		break;
	default:
		ERR("Failed to create firing-policy from payload, unhandled firing-policy type: firing-policy-type=%u (%s)",
				firing_policy_comm->firing_policy_type,
				lttng_firing_policy_type_string(firing_policy_comm->firing_policy_type));
		consumed_len = -1;
		goto end;
	}

	{
		/*
		 * Create buffer view for the firing_policy-type-specific data.
		 */
		struct lttng_payload_view specific_firing_policy_view =
				lttng_payload_view_from_view(view,
						sizeof(struct lttng_firing_policy_comm),
						-1);

		specific_firing_policy_consumed_len = create_from_payload_cb(
				&specific_firing_policy_view, firing_policy);
	}

	if (specific_firing_policy_consumed_len < 0) {
		ERR("Failed to create specific firing_policy from buffer");
		consumed_len = -1;
		goto end;
	}

	assert(*firing_policy);

	consumed_len = sizeof(struct lttng_firing_policy_comm) +
			specific_firing_policy_consumed_len;

end:
	return consumed_len;
}

LTTNG_HIDDEN
bool lttng_firing_policy_is_equal(const struct lttng_firing_policy *a,
		const struct lttng_firing_policy *b)
{
	bool is_equal = false;

	if (!a || !b) {
		goto end;
	}

	if (a->type != b->type) {
		goto end;
	}

	if (a == b) {
		is_equal = true;
		goto end;
	}

	assert(a->equal);
	is_equal = a->equal(a, b);
end:
	return is_equal;
}

LTTNG_HIDDEN
bool lttng_firing_policy_should_execute(
		const struct lttng_firing_policy *policy, uint64_t counter)
{
	switch (policy->type) {
	case LTTNG_FIRING_POLICY_TYPE_EVERY_N:
		return lttng_firing_policy_every_n_should_execute(
				policy, counter);
	case LTTNG_FIRING_POLICY_TYPE_ONCE_AFTER_N:
		return lttng_firing_policy_once_after_n_should_execute(
				policy, counter);
	default:
		abort();
		break;
	}
}

/* Every N */
static const struct lttng_firing_policy_every_n *
firing_policy_every_n_from_firing_policy_const(
		const struct lttng_firing_policy *policy)
{
	assert(policy);

	return container_of(policy, const struct lttng_firing_policy_every_n,
			parent);
}

static int lttng_firing_policy_every_n_serialize(
		struct lttng_firing_policy *policy,
		struct lttng_payload *payload)
{
	int ret;
	const struct lttng_firing_policy_every_n *every_n_policy;
	struct lttng_firing_policy_every_n_comm comm = {};

	assert(policy);
	assert(payload);

	every_n_policy = firing_policy_every_n_from_firing_policy_const(policy);
	comm.interval = every_n_policy->interval;

	ret = lttng_dynamic_buffer_append(
			&payload->buffer, &comm, sizeof(comm));
	return ret;
}

static bool lttng_firing_policy_every_n_is_equal(
		const struct lttng_firing_policy *_a,
		const struct lttng_firing_policy *_b)
{
	bool is_equal = false;
	const struct lttng_firing_policy_every_n *a, *b;

	a = firing_policy_every_n_from_firing_policy_const(_a);
	b = firing_policy_every_n_from_firing_policy_const(_b);

	if (a->interval != b->interval) {
		goto end;
	}

	is_equal = true;

end:
	return is_equal;
}

static void lttng_firing_policy_every_n_destroy(
		struct lttng_firing_policy *policy)
{
	/* Nothing type-specific to release. */
	free(policy);
}

static struct lttng_firing_policy *lttng_firing_policy_every_n_copy(
		const struct lttng_firing_policy *source)
{
	struct lttng_firing_policy *copy = NULL;
	const struct lttng_firing_policy_every_n *every_n_policy;

	if (!source) {
		goto end;
	}

	every_n_policy = firing_policy_every_n_from_firing_policy_const(source);
	copy = lttng_firing_policy_every_n_create(
			every_n_policy->interval);

end:
	return copy;
}

LTTNG_HIDDEN
struct lttng_firing_policy *lttng_firing_policy_every_n_create(
		uint64_t interval)
{
	struct lttng_firing_policy_every_n *policy = NULL;

	if (interval == 0) {
		/*
		 * An interval of 0 is invalid since it would never be fired.
		 */
		goto end;
	}

	policy = zmalloc(sizeof(struct lttng_firing_policy_every_n));
	if (!policy) {
		goto end;
	}

	lttng_firing_policy_init(&policy->parent,
			LTTNG_FIRING_POLICY_TYPE_EVERY_N,
			lttng_firing_policy_every_n_serialize,
			lttng_firing_policy_every_n_is_equal,
			lttng_firing_policy_every_n_destroy,
			lttng_firing_policy_every_n_copy);

	policy->interval = interval;

end:
	return policy ? &policy->parent : NULL;
}

LTTNG_HIDDEN
enum lttng_firing_policy_status lttng_firing_policy_every_n_get_interval(
		const struct lttng_firing_policy *policy, uint64_t *interval)
{
	const struct lttng_firing_policy_every_n *every_n_policy;
	enum lttng_firing_policy_status status;

	if (!policy || !IS_EVERY_N_FIRING_POLICY(policy) || !interval) {
		status = LTTNG_FIRING_POLICY_STATUS_INVALID;
		goto end;
	}

	every_n_policy = firing_policy_every_n_from_firing_policy_const(policy);
	*interval = every_n_policy->interval;
	status = LTTNG_FIRING_POLICY_STATUS_OK;
end:

	return status;
}

static bool lttng_firing_policy_every_n_should_execute(
		const struct lttng_firing_policy *policy, uint64_t counter)
{
	const struct lttng_firing_policy_every_n *every_n_policy;
	assert(policy);
	bool execute = false;

	every_n_policy = firing_policy_every_n_from_firing_policy_const(policy);

	if (every_n_policy->interval == 0) {
		abort();
	}

	execute = (counter % every_n_policy->interval) == 0;

	DBG("Policy every N = %" PRIu64
			": execution %s. Execution count: %" PRIu64,
			every_n_policy->interval,
			execute ? "accepted" : "denied", counter);

	return execute;
}

/* Once after N */

static const struct lttng_firing_policy_once_after_n *
firing_policy_once_after_n_from_firing_policy_const(
		const struct lttng_firing_policy *policy)
{
	assert(policy);

	return container_of(policy, struct lttng_firing_policy_once_after_n,
			parent);
}

static int lttng_firing_policy_once_after_n_serialize(
		struct lttng_firing_policy *policy,
		struct lttng_payload *payload)
{
	int ret;
	const struct lttng_firing_policy_once_after_n *once_after_n_policy;
	struct lttng_firing_policy_once_after_n_comm comm = {};

	assert(policy);
	assert(payload);

	once_after_n_policy =
			firing_policy_once_after_n_from_firing_policy_const(
					policy);
	comm.threshold = once_after_n_policy->threshold;

	ret = lttng_dynamic_buffer_append(
			&payload->buffer, &comm, sizeof(comm));
	return ret;
}

static bool lttng_firing_policy_once_after_n_is_equal(
		const struct lttng_firing_policy *_a,
		const struct lttng_firing_policy *_b)
{
	bool is_equal = false;
	const struct lttng_firing_policy_once_after_n *a, *b;

	a = firing_policy_once_after_n_from_firing_policy_const(_a);
	b = firing_policy_once_after_n_from_firing_policy_const(_b);

	if (a->threshold != b->threshold) {
		goto end;
	}

	is_equal = true;

end:
	return is_equal;
}

static void lttng_firing_policy_once_after_n_destroy(
		struct lttng_firing_policy *policy)
{
	/* Nothing type specific to release. */
	free(policy);
}

static struct lttng_firing_policy *lttng_firing_policy_once_after_n_copy(
		const struct lttng_firing_policy *source)
{
	struct lttng_firing_policy *copy = NULL;
	const struct lttng_firing_policy_once_after_n *once_after_n_policy;

	if (!source) {
		goto end;
	}

	once_after_n_policy =
			firing_policy_once_after_n_from_firing_policy_const(
					source);
	copy = lttng_firing_policy_once_after_n_create(
			once_after_n_policy->threshold);

end:
	return copy;
}

LTTNG_HIDDEN
struct lttng_firing_policy *lttng_firing_policy_once_after_n_create(
		uint64_t threshold)
{
	struct lttng_firing_policy_once_after_n *policy = NULL;

	if (threshold == 0) {
		/* threshold is expected to be > 0 */
		goto end;
	}

	policy = zmalloc(sizeof(struct lttng_firing_policy_once_after_n));
	if (!policy) {
		goto end;
	}

	lttng_firing_policy_init(&policy->parent,
			LTTNG_FIRING_POLICY_TYPE_ONCE_AFTER_N,
			lttng_firing_policy_once_after_n_serialize,
			lttng_firing_policy_once_after_n_is_equal,
			lttng_firing_policy_once_after_n_destroy,
			lttng_firing_policy_once_after_n_copy);

	policy->threshold = threshold;

end:
	return policy ? &policy->parent : NULL;
}

LTTNG_HIDDEN
enum lttng_firing_policy_status lttng_firing_policy_once_after_n_get_threshold(
		const struct lttng_firing_policy *policy, uint64_t *threshold)
{
	const struct lttng_firing_policy_once_after_n *once_after_n_policy;
	enum lttng_firing_policy_status status;

	if (!policy || !IS_ONCE_AFTER_N_FIRING_POLICY(policy) || !threshold) {
		status = LTTNG_FIRING_POLICY_STATUS_INVALID;
		goto end;
	}

	once_after_n_policy =
			firing_policy_once_after_n_from_firing_policy_const(
					policy);
	*threshold = once_after_n_policy->threshold;
	status = LTTNG_FIRING_POLICY_STATUS_OK;

end:
	return status;
}

LTTNG_HIDDEN
struct lttng_firing_policy *lttng_firing_policy_copy(
		const struct lttng_firing_policy *source)
{
	assert(source->copy);
	return source->copy(source);
}

static bool lttng_firing_policy_once_after_n_should_execute(
		const struct lttng_firing_policy *policy, uint64_t counter)
{
	const struct lttng_firing_policy_once_after_n *once_after_n_policy;
	bool execute = false;
	assert(policy);

	once_after_n_policy =
			firing_policy_once_after_n_from_firing_policy_const(
					policy);

	execute = counter == once_after_n_policy->threshold;

	DBG("Policy once after N = %" PRIu64
	    ": execution %s. Execution count: %" PRIu64,
			once_after_n_policy->threshold,
			execute ? "accepted" : "denied", counter);

	return counter == once_after_n_policy->threshold;
}
