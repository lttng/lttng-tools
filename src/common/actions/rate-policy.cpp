/*
 * Copyright (C) 2021 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/buffer-view.hpp>
#include <common/dynamic-buffer.hpp>
#include <common/error.hpp>
#include <common/macros.hpp>
#include <common/mi-lttng.hpp>
#include <common/payload-view.hpp>
#include <common/payload.hpp>
#include <limits.h>
#include <lttng/action/rate-policy-internal.hpp>
#include <lttng/action/rate-policy.h>
#include <stdbool.h>
#include <sys/types.h>

#define IS_EVERY_N_RATE_POLICY(policy) \
	(lttng_rate_policy_get_type(policy) == LTTNG_RATE_POLICY_TYPE_EVERY_N)

#define IS_ONCE_AFTER_N_RATE_POLICY(policy)    \
	(lttng_rate_policy_get_type(policy) == \
			LTTNG_RATE_POLICY_TYPE_ONCE_AFTER_N)

typedef void (*rate_policy_destroy_cb)(struct lttng_rate_policy *rate_policy);
typedef int (*rate_policy_serialize_cb)(struct lttng_rate_policy *rate_policy,
		struct lttng_payload *payload);
typedef bool (*rate_policy_equal_cb)(const struct lttng_rate_policy *a,
		const struct lttng_rate_policy *b);
typedef ssize_t (*rate_policy_create_from_payload_cb)(
		struct lttng_payload_view *view,
		struct lttng_rate_policy **rate_policy);
typedef struct lttng_rate_policy *(*rate_policy_copy_cb)(
		const struct lttng_rate_policy *source);
typedef enum lttng_error_code (*rate_policy_mi_serialize_cb)(
		const struct lttng_rate_policy *rate_policy,
		struct mi_writer *writer);

struct lttng_rate_policy {
	enum lttng_rate_policy_type type;
	rate_policy_serialize_cb serialize;
	rate_policy_equal_cb equal;
	rate_policy_destroy_cb destroy;
	rate_policy_copy_cb copy;
	rate_policy_mi_serialize_cb mi_serialize;
};

struct lttng_rate_policy_every_n {
	struct lttng_rate_policy parent;
	uint64_t interval;
};

struct lttng_rate_policy_once_after_n {
	struct lttng_rate_policy parent;
	uint64_t threshold;
};

struct lttng_rate_policy_comm {
	/* enum lttng_rate_policy_type */
	int8_t rate_policy_type;
} LTTNG_PACKED;

struct lttng_rate_policy_once_after_n_comm {
	uint64_t threshold;
} LTTNG_PACKED;

struct lttng_rate_policy_every_n_comm {
	uint64_t interval;
} LTTNG_PACKED;

/* Forward declaration. */
static void lttng_rate_policy_init(struct lttng_rate_policy *rate_policy,
		enum lttng_rate_policy_type type,
		rate_policy_serialize_cb serialize,
		rate_policy_equal_cb equal,
		rate_policy_destroy_cb destroy,
		rate_policy_copy_cb copy,
		rate_policy_mi_serialize_cb mi);

/* Forward declaration. Every n */
static bool lttng_rate_policy_every_n_should_execute(
		const struct lttng_rate_policy *policy, uint64_t counter);

/* Forward declaration. Once after N */
static bool lttng_rate_policy_once_after_n_should_execute(
		const struct lttng_rate_policy *policy, uint64_t counter);

const char *lttng_rate_policy_type_string(
		enum lttng_rate_policy_type rate_policy_type)
{
	switch (rate_policy_type) {
	case LTTNG_RATE_POLICY_TYPE_EVERY_N:
		return "EVERY-N";
	case LTTNG_RATE_POLICY_TYPE_ONCE_AFTER_N:
		return "ONCE-AFTER-N";
	default:
		return "???";
	}
}

enum lttng_rate_policy_type lttng_rate_policy_get_type(
		const struct lttng_rate_policy *policy)
{
	return policy ? policy->type : LTTNG_RATE_POLICY_TYPE_UNKNOWN;
}

void lttng_rate_policy_init(struct lttng_rate_policy *rate_policy,
		enum lttng_rate_policy_type type,
		rate_policy_serialize_cb serialize,
		rate_policy_equal_cb equal,
		rate_policy_destroy_cb destroy,
		rate_policy_copy_cb copy,
		rate_policy_mi_serialize_cb mi)
{
	rate_policy->type = type;
	rate_policy->serialize = serialize;
	rate_policy->equal = equal;
	rate_policy->destroy = destroy;
	rate_policy->copy = copy;
	rate_policy->mi_serialize = mi;
}

void lttng_rate_policy_destroy(struct lttng_rate_policy *rate_policy)
{
	if (!rate_policy) {
		return;
	}

	rate_policy->destroy(rate_policy);
}

int lttng_rate_policy_serialize(struct lttng_rate_policy *rate_policy,
		struct lttng_payload *payload)
{
	int ret;
	struct lttng_rate_policy_comm rate_policy_comm = {
			.rate_policy_type = (int8_t) rate_policy->type,
	};

	ret = lttng_dynamic_buffer_append(&payload->buffer, &rate_policy_comm,
			sizeof(rate_policy_comm));
	if (ret) {
		goto end;
	}

	ret = rate_policy->serialize(rate_policy, payload);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

static ssize_t lttng_rate_policy_once_after_n_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_rate_policy **rate_policy)
{
	ssize_t consumed_len = -1;
	struct lttng_rate_policy *policy = NULL;
	const struct lttng_rate_policy_once_after_n_comm *comm;
	const struct lttng_payload_view comm_view =
			lttng_payload_view_from_view(view, 0, sizeof(*comm));

	if (!view || !rate_policy) {
		consumed_len = -1;
		goto end;
	}

	if (!lttng_payload_view_is_valid(&comm_view)) {
		/* Payload not large enough to contain the header. */
		consumed_len = -1;
		goto end;
	}

	comm = (const struct lttng_rate_policy_once_after_n_comm *)
			       comm_view.buffer.data;

	policy = lttng_rate_policy_once_after_n_create(comm->threshold);
	if (policy == NULL) {
		consumed_len = -1;
		goto end;
	}

	*rate_policy = policy;
	consumed_len = sizeof(*comm);

end:
	return consumed_len;
}

static ssize_t lttng_rate_policy_every_n_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_rate_policy **rate_policy)
{
	ssize_t consumed_len = -1;
	struct lttng_rate_policy *policy = NULL;
	const struct lttng_rate_policy_every_n_comm *comm;
	const struct lttng_payload_view comm_view =
			lttng_payload_view_from_view(view, 0, sizeof(*comm));

	if (!view || !rate_policy) {
		consumed_len = -1;
		goto end;
	}

	if (!lttng_payload_view_is_valid(&comm_view)) {
		/* Payload not large enough to contain the header. */
		consumed_len = -1;
		goto end;
	}

	comm = (const struct lttng_rate_policy_every_n_comm *)
			       comm_view.buffer.data;

	policy = lttng_rate_policy_every_n_create(comm->interval);
	if (policy == NULL) {
		consumed_len = -1;
		goto end;
	}

	*rate_policy = policy;
	consumed_len = sizeof(*comm);

end:
	return consumed_len;
}

ssize_t lttng_rate_policy_create_from_payload(struct lttng_payload_view *view,
		struct lttng_rate_policy **rate_policy)
{
	ssize_t consumed_len, specific_rate_policy_consumed_len;
	rate_policy_create_from_payload_cb create_from_payload_cb;
	const struct lttng_rate_policy_comm *rate_policy_comm;
	const struct lttng_payload_view rate_policy_comm_view =
		lttng_payload_view_from_view(
			view, 0, sizeof(*rate_policy_comm));

	if (!view || !rate_policy) {
		consumed_len = -1;
		goto end;
	}

	if (!lttng_payload_view_is_valid(&rate_policy_comm_view)) {
		/* Payload not large enough to contain the header. */
		consumed_len = -1;
		goto end;
	}

	rate_policy_comm = (const struct lttng_rate_policy_comm *)
					   rate_policy_comm_view.buffer.data;

	DBG("Create rate_policy from payload: rate-policy-type=%s",
		lttng_rate_policy_type_string(
			(lttng_rate_policy_type) rate_policy_comm->rate_policy_type));

	switch (rate_policy_comm->rate_policy_type) {
	case LTTNG_RATE_POLICY_TYPE_EVERY_N:
		create_from_payload_cb =
				lttng_rate_policy_every_n_create_from_payload;
		break;
	case LTTNG_RATE_POLICY_TYPE_ONCE_AFTER_N:
		create_from_payload_cb =
				lttng_rate_policy_once_after_n_create_from_payload;
		break;
	default:
		ERR("Failed to create rate-policy from payload, unhandled rate-policy type: rate-policy-type=%u (%s)",
				rate_policy_comm->rate_policy_type,
				lttng_rate_policy_type_string(
					(lttng_rate_policy_type) rate_policy_comm->rate_policy_type));
		consumed_len = -1;
		goto end;
	}

	{
		/* Create buffer view for the rate_policy-type-specific data.
		 */
		struct lttng_payload_view specific_rate_policy_view =
				lttng_payload_view_from_view(view,
						sizeof(struct lttng_rate_policy_comm),
						-1);

		specific_rate_policy_consumed_len = create_from_payload_cb(
				&specific_rate_policy_view, rate_policy);
	}
	if (specific_rate_policy_consumed_len < 0) {
		ERR("Failed to create specific rate_policy from buffer.");
		consumed_len = -1;
		goto end;
	}

	LTTNG_ASSERT(*rate_policy);

	consumed_len = sizeof(struct lttng_rate_policy_comm) +
			specific_rate_policy_consumed_len;

end:
	return consumed_len;
}

bool lttng_rate_policy_is_equal(const struct lttng_rate_policy *a,
		const struct lttng_rate_policy *b)
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

	LTTNG_ASSERT(a->equal);
	is_equal = a->equal(a, b);
end:
	return is_equal;
}

bool lttng_rate_policy_should_execute(
		const struct lttng_rate_policy *policy, uint64_t counter)
{
	switch (policy->type) {
	case LTTNG_RATE_POLICY_TYPE_EVERY_N:
		return lttng_rate_policy_every_n_should_execute(
				policy, counter);
	case LTTNG_RATE_POLICY_TYPE_ONCE_AFTER_N:
		return lttng_rate_policy_once_after_n_should_execute(
				policy, counter);
	default:
		abort();
		break;
	}
}

/* Every N */
static struct lttng_rate_policy_every_n *rate_policy_every_n_from_rate_policy(
		struct lttng_rate_policy *policy)
{
	LTTNG_ASSERT(policy);

	return container_of(policy, struct lttng_rate_policy_every_n, parent);
}

static const struct lttng_rate_policy_every_n *
rate_policy_every_n_from_rate_policy_const(
		const struct lttng_rate_policy *policy)
{
	LTTNG_ASSERT(policy);

	return container_of(policy, struct lttng_rate_policy_every_n, parent);
}

static int lttng_rate_policy_every_n_serialize(
		struct lttng_rate_policy *policy, struct lttng_payload *payload)
{
	int ret;

	struct lttng_rate_policy_every_n *every_n_policy;
	struct lttng_rate_policy_every_n_comm comm = {};

	LTTNG_ASSERT(policy);
	LTTNG_ASSERT(payload);

	every_n_policy = rate_policy_every_n_from_rate_policy(policy);
	comm.interval = every_n_policy->interval;

	ret = lttng_dynamic_buffer_append(
			&payload->buffer, &comm, sizeof(comm));
	return ret;
}

static bool lttng_rate_policy_every_n_is_equal(
		const struct lttng_rate_policy *_a,
		const struct lttng_rate_policy *_b)
{
	bool is_equal = false;
	const struct lttng_rate_policy_every_n *a, *b;

	a = rate_policy_every_n_from_rate_policy_const(_a);
	b = rate_policy_every_n_from_rate_policy_const(_b);

	if (a->interval != b->interval) {
		goto end;
	}

	is_equal = true;

end:
	return is_equal;
}

static void lttng_rate_policy_every_n_destroy(struct lttng_rate_policy *policy)
{
	struct lttng_rate_policy_every_n *every_n_policy;

	if (!policy) {
		goto end;
	}

	every_n_policy = rate_policy_every_n_from_rate_policy(policy);

	free(every_n_policy);

end:
	return;
}

static struct lttng_rate_policy *lttng_rate_policy_every_n_copy(
		const struct lttng_rate_policy *source)
{
	struct lttng_rate_policy *copy = NULL;
	const struct lttng_rate_policy_every_n *every_n_policy;

	if (!source) {
		goto end;
	}

	every_n_policy = rate_policy_every_n_from_rate_policy_const(source);
	copy = lttng_rate_policy_every_n_create(every_n_policy->interval);

end:
	return copy;
}

static enum lttng_error_code lttng_rate_policy_every_n_mi_serialize(
		const struct lttng_rate_policy *rate_policy,
		struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;
	const struct lttng_rate_policy_every_n *every_n_policy = NULL;

	LTTNG_ASSERT(rate_policy);
	LTTNG_ASSERT(IS_EVERY_N_RATE_POLICY(rate_policy));
	LTTNG_ASSERT(writer);

	every_n_policy = rate_policy_every_n_from_rate_policy_const(
			rate_policy);

	/* Open rate_policy_every_n element. */
	ret = mi_lttng_writer_open_element(
			writer, mi_lttng_element_rate_policy_every_n);
	if (ret) {
		goto mi_error;
	}

	/* Interval. */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			mi_lttng_element_rate_policy_every_n_interval,
			every_n_policy->interval);
	if (ret) {
		goto mi_error;
	}

	/* Close rate_policy_every_n element. */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto mi_error;
	}

	ret_code = LTTNG_OK;
	goto end;

mi_error:
	ret_code = LTTNG_ERR_MI_IO_FAIL;
end:
	return ret_code;
}

struct lttng_rate_policy *lttng_rate_policy_every_n_create(uint64_t interval)
{
	struct lttng_rate_policy_every_n *policy = NULL;
	struct lttng_rate_policy *_policy = NULL;

	if (interval == 0) {
		/*
		 * An interval of 0 is invalid since it would never be fired.
		 */
		goto end;
	}

	policy = zmalloc<lttng_rate_policy_every_n>();
	if (!policy) {
		goto end;
	}

	lttng_rate_policy_init(&policy->parent, LTTNG_RATE_POLICY_TYPE_EVERY_N,
			lttng_rate_policy_every_n_serialize,
			lttng_rate_policy_every_n_is_equal,
			lttng_rate_policy_every_n_destroy,
			lttng_rate_policy_every_n_copy,
			lttng_rate_policy_every_n_mi_serialize);

	policy->interval = interval;

	_policy = &policy->parent;
	policy = NULL;

end:
	free(policy);
	return _policy;
}

enum lttng_rate_policy_status lttng_rate_policy_every_n_get_interval(
		const struct lttng_rate_policy *policy, uint64_t *interval)
{
	const struct lttng_rate_policy_every_n *every_n_policy;
	enum lttng_rate_policy_status status;

	if (!policy || !IS_EVERY_N_RATE_POLICY(policy) || !interval) {
		status = LTTNG_RATE_POLICY_STATUS_INVALID;
		goto end;
	}

	every_n_policy = rate_policy_every_n_from_rate_policy_const(policy);
	*interval = every_n_policy->interval;
	status = LTTNG_RATE_POLICY_STATUS_OK;
end:

	return status;
}

static bool lttng_rate_policy_every_n_should_execute(
		const struct lttng_rate_policy *policy, uint64_t counter)
{
	const struct lttng_rate_policy_every_n *every_n_policy;
	LTTNG_ASSERT(policy);
	bool execute = false;

	every_n_policy = rate_policy_every_n_from_rate_policy_const(policy);

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

static struct lttng_rate_policy_once_after_n *
rate_policy_once_after_n_from_rate_policy(struct lttng_rate_policy *policy)
{
	LTTNG_ASSERT(policy);

	return container_of(
			policy, struct lttng_rate_policy_once_after_n, parent);
}

static const struct lttng_rate_policy_once_after_n *
rate_policy_once_after_n_from_rate_policy_const(
		const struct lttng_rate_policy *policy)
{
	LTTNG_ASSERT(policy);

	return container_of(
			policy, struct lttng_rate_policy_once_after_n, parent);
}
static int lttng_rate_policy_once_after_n_serialize(
		struct lttng_rate_policy *policy, struct lttng_payload *payload)
{
	int ret;

	struct lttng_rate_policy_once_after_n *once_after_n_policy;
	struct lttng_rate_policy_once_after_n_comm comm = {};

	LTTNG_ASSERT(policy);
	LTTNG_ASSERT(payload);

	once_after_n_policy = rate_policy_once_after_n_from_rate_policy(policy);
	comm.threshold = once_after_n_policy->threshold;

	ret = lttng_dynamic_buffer_append(
			&payload->buffer, &comm, sizeof(comm));
	return ret;
}

static bool lttng_rate_policy_once_after_n_is_equal(
		const struct lttng_rate_policy *_a,
		const struct lttng_rate_policy *_b)
{
	bool is_equal = false;
	const struct lttng_rate_policy_once_after_n *a, *b;

	a = rate_policy_once_after_n_from_rate_policy_const(_a);
	b = rate_policy_once_after_n_from_rate_policy_const(_b);

	if (a->threshold != b->threshold) {
		goto end;
	}

	is_equal = true;

end:
	return is_equal;
}

static void lttng_rate_policy_once_after_n_destroy(
		struct lttng_rate_policy *policy)
{
	struct lttng_rate_policy_once_after_n *once_after_n_policy;

	if (!policy) {
		goto end;
	}

	once_after_n_policy = rate_policy_once_after_n_from_rate_policy(policy);

	free(once_after_n_policy);

end:
	return;
}

static struct lttng_rate_policy *lttng_rate_policy_once_after_n_copy(
		const struct lttng_rate_policy *source)
{
	struct lttng_rate_policy *copy = NULL;
	const struct lttng_rate_policy_once_after_n *once_after_n_policy;

	if (!source) {
		goto end;
	}

	once_after_n_policy =
			rate_policy_once_after_n_from_rate_policy_const(source);
	copy = lttng_rate_policy_once_after_n_create(
			once_after_n_policy->threshold);

end:
	return copy;
}

static enum lttng_error_code lttng_rate_policy_once_after_n_mi_serialize(
		const struct lttng_rate_policy *rate_policy,
		struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;
	const struct lttng_rate_policy_once_after_n *once_after_n_policy = NULL;

	LTTNG_ASSERT(rate_policy);
	LTTNG_ASSERT(IS_ONCE_AFTER_N_RATE_POLICY(rate_policy));
	LTTNG_ASSERT(writer);

	once_after_n_policy = rate_policy_once_after_n_from_rate_policy_const(
			rate_policy);

	/* Open rate_policy_once_after_n. */
	ret = mi_lttng_writer_open_element(
			writer, mi_lttng_element_rate_policy_once_after_n);
	if (ret) {
		goto mi_error;
	}

	/* Threshold. */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			mi_lttng_element_rate_policy_once_after_n_threshold,
			once_after_n_policy->threshold);
	if (ret) {
		goto mi_error;
	}

	/* Close rate_policy_once_after_n element. */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto mi_error;
	}

	ret_code = LTTNG_OK;
	goto end;

mi_error:
	ret_code = LTTNG_ERR_MI_IO_FAIL;
end:
	return ret_code;
}

struct lttng_rate_policy *lttng_rate_policy_once_after_n_create(
		uint64_t threshold)
{
	struct lttng_rate_policy_once_after_n *policy = NULL;
	struct lttng_rate_policy *_policy = NULL;

	if (threshold == 0) {
		/* threshold is expected to be > 0 */
		goto end;
	}

	policy = zmalloc<lttng_rate_policy_once_after_n>();
	if (!policy) {
		goto end;
	}

	lttng_rate_policy_init(&policy->parent,
			LTTNG_RATE_POLICY_TYPE_ONCE_AFTER_N,
			lttng_rate_policy_once_after_n_serialize,
			lttng_rate_policy_once_after_n_is_equal,
			lttng_rate_policy_once_after_n_destroy,
			lttng_rate_policy_once_after_n_copy,
			lttng_rate_policy_once_after_n_mi_serialize);

	policy->threshold = threshold;

	_policy = &policy->parent;
	policy = NULL;

end:
	free(policy);
	return _policy;
}

enum lttng_rate_policy_status lttng_rate_policy_once_after_n_get_threshold(
		const struct lttng_rate_policy *policy, uint64_t *threshold)
{
	const struct lttng_rate_policy_once_after_n *once_after_n_policy;
	enum lttng_rate_policy_status status;

	if (!policy || !IS_ONCE_AFTER_N_RATE_POLICY(policy) || !threshold) {
		status = LTTNG_RATE_POLICY_STATUS_INVALID;
		goto end;
	}

	once_after_n_policy =
			rate_policy_once_after_n_from_rate_policy_const(policy);
	*threshold = once_after_n_policy->threshold;
	status = LTTNG_RATE_POLICY_STATUS_OK;
end:

	return status;
}

struct lttng_rate_policy *lttng_rate_policy_copy(
		const struct lttng_rate_policy *source)
{
	LTTNG_ASSERT(source->copy);
	return source->copy(source);
}

static bool lttng_rate_policy_once_after_n_should_execute(
		const struct lttng_rate_policy *policy, uint64_t counter)
{
	const struct lttng_rate_policy_once_after_n *once_after_n_policy;
	bool execute = false;
	LTTNG_ASSERT(policy);

	once_after_n_policy =
			rate_policy_once_after_n_from_rate_policy_const(policy);

	execute = counter == once_after_n_policy->threshold;

	DBG("Policy once after N = %" PRIu64
	    ": execution %s. Execution count: %" PRIu64,
			once_after_n_policy->threshold,
			execute ? "accepted" : "denied", counter);

	return counter == once_after_n_policy->threshold;
}

enum lttng_error_code lttng_rate_policy_mi_serialize(
		const struct lttng_rate_policy *rate_policy,
		struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;

	LTTNG_ASSERT(rate_policy);
	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(rate_policy->mi_serialize);

	/* Open rate policy element. */
	ret = mi_lttng_writer_open_element(
			writer, mi_lttng_element_rate_policy);
	if (ret) {
		goto mi_error;
	}

	/* Serialize underlying rate policy. */
	ret_code = rate_policy->mi_serialize(rate_policy, writer);
	if (ret_code != LTTNG_OK) {
		goto end;
	}

	/* Close rate policy element. */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto mi_error;
	}

	ret_code = LTTNG_OK;
	goto end;

mi_error:
	ret_code = LTTNG_ERR_MI_IO_FAIL;
end:
	return ret_code;
}
