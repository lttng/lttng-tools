/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/error.h>
#include <common/macros.h>
#include <common/mi-lttng.h>
#include <lttng/action/action-internal.h>
#include <lttng/action/notify-internal.h>
#include <lttng/action/rate-policy-internal.h>
#include <lttng/lttng-error.h>

#define IS_NOTIFY_ACTION(action) \
	(lttng_action_get_type(action) == LTTNG_ACTION_TYPE_NOTIFY)

static struct lttng_action_notify *action_notify_from_action(
		struct lttng_action *action)
{
	LTTNG_ASSERT(action);

	return container_of(action, struct lttng_action_notify, parent);
}

static const struct lttng_action_notify *action_notify_from_action_const(
		const struct lttng_action *action)
{
	LTTNG_ASSERT(action);

	return container_of(action, struct lttng_action_notify, parent);
}

static
void lttng_action_notify_destroy(struct lttng_action *action)
{
	struct lttng_action_notify *notify_action;
	notify_action = action_notify_from_action(action);
	lttng_rate_policy_destroy(notify_action->policy);
	free(notify_action);
}

static
int lttng_action_notify_serialize(struct lttng_action *action,
		struct lttng_payload *payload)
{
	int ret;
	struct lttng_action_notify *notify_action;

	if (!action || !IS_NOTIFY_ACTION(action) || !payload) {
		ret = -1;
		goto end;
	}

	DBG("Serializing notify action");

	notify_action = action_notify_from_action(action);
	DBG("Serializing notify action rate policy");
	ret = lttng_rate_policy_serialize(notify_action->policy, payload);

end:
	return ret;
}

static
bool lttng_action_notify_is_equal(const struct lttng_action *a,
		const struct lttng_action *b)
{
	const struct lttng_action_notify *_a, *_b;

	_a = action_notify_from_action_const(a);
	_b = action_notify_from_action_const(b);
	return lttng_rate_policy_is_equal(_a->policy, _b->policy);
}

static const struct lttng_rate_policy *
lttng_action_notify_internal_get_rate_policy(const struct lttng_action *action)
{
	const struct lttng_action_notify *_action;
	_action = action_notify_from_action_const(action);

	return _action->policy;
}

static enum lttng_error_code lttng_action_notify_mi_serialize(
		const struct lttng_action *action, struct mi_writer *writer)
{
	int ret;
	enum lttng_action_status status;
	enum lttng_error_code ret_code;
	const struct lttng_rate_policy *policy = NULL;

	LTTNG_ASSERT(action);
	LTTNG_ASSERT(IS_NOTIFY_ACTION(action));
	LTTNG_ASSERT(writer);

	status = lttng_action_notify_get_rate_policy(action, &policy);
	LTTNG_ASSERT(status == LTTNG_ACTION_STATUS_OK);
	LTTNG_ASSERT(policy != NULL);

	/* Open action notify. */
	ret = mi_lttng_writer_open_element(
			writer, mi_lttng_element_action_notify);
	if (ret) {
		goto mi_error;
	}

	ret_code = lttng_rate_policy_mi_serialize(policy, writer);
	if (ret_code != LTTNG_OK) {
		goto end;
	}

	/* Close action notify element. */
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

struct lttng_action *lttng_action_notify_create(void)
{
	struct lttng_rate_policy *policy = NULL;
	struct lttng_action_notify *notify = NULL;
	struct lttng_action *action = NULL;

	notify = zmalloc(sizeof(struct lttng_action_notify));
	if (!notify) {
		goto end;
	}

	/* Default policy. */
	policy = lttng_rate_policy_every_n_create(1);
	if (!policy) {
		goto end;
	}

	lttng_action_init(&notify->parent, LTTNG_ACTION_TYPE_NOTIFY, NULL,
			lttng_action_notify_serialize,
			lttng_action_notify_is_equal,
			lttng_action_notify_destroy,
			lttng_action_notify_internal_get_rate_policy,
			lttng_action_generic_add_error_query_results,
			lttng_action_notify_mi_serialize);

	notify->policy = policy;
	policy = NULL;

	action = &notify->parent;
	notify = NULL;

end:
	free(notify);
	lttng_rate_policy_destroy(policy);
	return action;
}

ssize_t lttng_action_notify_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_action **action)
{
	enum lttng_action_status status;
	ssize_t consumed_length;
	struct lttng_rate_policy *rate_policy = NULL;
	struct lttng_action *_action = NULL;

	consumed_length = lttng_rate_policy_create_from_payload(
			view, &rate_policy);
	if (!rate_policy) {
		consumed_length = -1;
		goto end;
	}

	_action = lttng_action_notify_create();
	if (!_action) {
		consumed_length = -1;
		goto end;
	}

	status = lttng_action_notify_set_rate_policy(_action, rate_policy);
	if (status != LTTNG_ACTION_STATUS_OK) {
		consumed_length = -1;
		goto end;
	}

	*action = _action;
	_action = NULL;

end:
	lttng_rate_policy_destroy(rate_policy);
	lttng_action_destroy(_action);
	return consumed_length;
}

enum lttng_action_status lttng_action_notify_set_rate_policy(
		struct lttng_action *action,
		const struct lttng_rate_policy *policy)
{
	enum lttng_action_status status;
	struct lttng_action_notify *notify_action;
	struct lttng_rate_policy *copy = NULL;

	if (!action || !policy || !IS_NOTIFY_ACTION(action)) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	copy = lttng_rate_policy_copy(policy);
	if (!copy) {
		status = LTTNG_ACTION_STATUS_ERROR;
		goto end;
	}

	notify_action = action_notify_from_action(action);

	/* Free the previous rate policy .*/
	lttng_rate_policy_destroy(notify_action->policy);

	/* Assign the policy. */
	notify_action->policy = copy;
	status = LTTNG_ACTION_STATUS_OK;
	copy = NULL;

end:
	lttng_rate_policy_destroy(copy);
	return status;
}

enum lttng_action_status lttng_action_notify_get_rate_policy(
		const struct lttng_action *action,
		const struct lttng_rate_policy **policy)
{
	enum lttng_action_status status;
	const struct lttng_action_notify *notify_action;

	if (!action || !policy || !IS_NOTIFY_ACTION(action)) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	notify_action = action_notify_from_action_const(action);

	*policy = notify_action->policy;
	status = LTTNG_ACTION_STATUS_OK;
end:
	return status;
}
