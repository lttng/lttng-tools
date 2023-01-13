/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/error.hpp>
#include <common/macros.hpp>
#include <common/mi-lttng.hpp>

#include <lttng/condition/buffer-usage-internal.hpp>
#include <lttng/condition/condition-internal.hpp>

#include <float.h>
#include <math.h>
#include <time.h>

#define IS_USAGE_CONDITION(condition)                                                    \
	(lttng_condition_get_type(condition) == LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW || \
	 lttng_condition_get_type(condition) == LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH)

static bool is_usage_evaluation(const struct lttng_evaluation *evaluation)
{
	enum lttng_condition_type type = lttng_evaluation_get_type(evaluation);

	return type == LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW ||
		type == LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH;
}

static void lttng_condition_buffer_usage_destroy(struct lttng_condition *condition)
{
	struct lttng_condition_buffer_usage *usage;

	usage = lttng::utils::container_of(condition, &lttng_condition_buffer_usage::parent);

	free(usage->session_name);
	free(usage->channel_name);
	free(usage);
}

static bool lttng_condition_buffer_usage_validate(const struct lttng_condition *condition)
{
	bool valid = false;
	struct lttng_condition_buffer_usage *usage;

	if (!condition) {
		goto end;
	}

	usage = lttng::utils::container_of(condition, &lttng_condition_buffer_usage::parent);
	if (!usage->session_name) {
		ERR("Invalid buffer condition: a target session name must be set.");
		goto end;
	}
	if (!usage->channel_name) {
		ERR("Invalid buffer condition: a target channel name must be set.");
		goto end;
	}
	if (usage->threshold_ratio.set == usage->threshold_bytes.set) {
		ERR("Invalid buffer condition: a threshold must be set or both type cannot be used simultaneously.");
		goto end;
	}
	if (!usage->domain.set) {
		ERR("Invalid buffer usage condition: a domain must be set.");
		goto end;
	}

	valid = true;
end:
	return valid;
}

static int lttng_condition_buffer_usage_serialize(const struct lttng_condition *condition,
						  struct lttng_payload *payload)
{
	int ret;
	struct lttng_condition_buffer_usage *usage;
	size_t session_name_len, channel_name_len;
	struct lttng_condition_buffer_usage_comm usage_comm = {};

	if (!condition || !IS_USAGE_CONDITION(condition)) {
		ret = -1;
		goto end;
	}

	DBG("Serializing buffer usage condition");
	usage = lttng::utils::container_of(condition, &lttng_condition_buffer_usage::parent);

	session_name_len = strlen(usage->session_name) + 1;
	channel_name_len = strlen(usage->channel_name) + 1;
	if (session_name_len > LTTNG_NAME_MAX || channel_name_len > LTTNG_NAME_MAX) {
		ret = -1;
		goto end;
	}

	usage_comm.threshold_set_in_bytes = !!usage->threshold_bytes.set;
	usage_comm.session_name_len = session_name_len;
	usage_comm.channel_name_len = channel_name_len;
	usage_comm.domain_type = (int8_t) usage->domain.type;

	if (usage->threshold_bytes.set) {
		usage_comm.threshold_bytes = usage->threshold_bytes.value;
	} else {
		usage_comm.threshold_ratio = usage->threshold_ratio.value;
	}

	ret = lttng_dynamic_buffer_append(&payload->buffer, &usage_comm, sizeof(usage_comm));
	if (ret) {
		goto end;
	}

	ret = lttng_dynamic_buffer_append(&payload->buffer, usage->session_name, session_name_len);
	if (ret) {
		goto end;
	}

	ret = lttng_dynamic_buffer_append(&payload->buffer, usage->channel_name, channel_name_len);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

static bool lttng_condition_buffer_usage_is_equal(const struct lttng_condition *_a,
						  const struct lttng_condition *_b)
{
	bool is_equal = false;
	struct lttng_condition_buffer_usage *a, *b;

	a = lttng::utils::container_of(_a, &lttng_condition_buffer_usage::parent);
	b = lttng::utils::container_of(_b, &lttng_condition_buffer_usage::parent);

	if ((a->threshold_ratio.set && !b->threshold_ratio.set) ||
	    (a->threshold_bytes.set && !b->threshold_bytes.set)) {
		goto end;
	}

	if (a->threshold_ratio.set && b->threshold_ratio.set) {
		double a_value, b_value, diff;

		a_value = a->threshold_ratio.value;
		b_value = b->threshold_ratio.value;
		diff = fabs(a_value - b_value);

		if (diff > DBL_EPSILON) {
			goto end;
		}
	} else if (a->threshold_bytes.set && b->threshold_bytes.set) {
		uint64_t a_value, b_value;

		a_value = a->threshold_bytes.value;
		b_value = b->threshold_bytes.value;
		if (a_value != b_value) {
			goto end;
		}
	}

	/* Condition is not valid if this is not true. */
	LTTNG_ASSERT(a->session_name);
	LTTNG_ASSERT(b->session_name);
	if (strcmp(a->session_name, b->session_name)) {
		goto end;
	}

	LTTNG_ASSERT(a->channel_name);
	LTTNG_ASSERT(b->channel_name);
	if (strcmp(a->channel_name, b->channel_name)) {
		goto end;
	}

	LTTNG_ASSERT(a->domain.set);
	LTTNG_ASSERT(b->domain.set);
	if (a->domain.type != b->domain.type) {
		goto end;
	}
	is_equal = true;
end:
	return is_equal;
}

static enum lttng_error_code
lttng_condition_buffer_usage_mi_serialize(const struct lttng_condition *condition,
					  struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;
	enum lttng_condition_status status;
	const char *session_name = NULL, *channel_name = NULL;
	enum lttng_domain_type domain_type;
	bool is_threshold_bytes = false;
	double threshold_ratio;
	uint64_t threshold_bytes;
	const char *condition_type_str = NULL;

	LTTNG_ASSERT(condition);
	LTTNG_ASSERT(IS_USAGE_CONDITION(condition));

	status = lttng_condition_buffer_usage_get_session_name(condition, &session_name);
	LTTNG_ASSERT(status == LTTNG_CONDITION_STATUS_OK);
	LTTNG_ASSERT(session_name);

	status = lttng_condition_buffer_usage_get_channel_name(condition, &channel_name);
	LTTNG_ASSERT(status == LTTNG_CONDITION_STATUS_OK);
	LTTNG_ASSERT(session_name);

	status = lttng_condition_buffer_usage_get_domain_type(condition, &domain_type);
	LTTNG_ASSERT(status == LTTNG_CONDITION_STATUS_OK);

	status = lttng_condition_buffer_usage_get_threshold(condition, &threshold_bytes);
	if (status == LTTNG_CONDITION_STATUS_OK) {
		is_threshold_bytes = true;
	} else if (status != LTTNG_CONDITION_STATUS_UNSET) {
		/* Unexpected at this stage. */
		ret_code = LTTNG_ERR_INVALID;
		goto end;
	}

	if (!is_threshold_bytes) {
		status = lttng_condition_buffer_usage_get_threshold_ratio(condition,
									  &threshold_ratio);
		LTTNG_ASSERT(status == LTTNG_CONDITION_STATUS_OK);
	}

	switch (lttng_condition_get_type(condition)) {
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
		condition_type_str = mi_lttng_element_condition_buffer_usage_high;
		break;
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
		condition_type_str = mi_lttng_element_condition_buffer_usage_low;
		break;
	default:
		abort();
		break;
	}

	/* Open the sub type condition element. */
	ret = mi_lttng_writer_open_element(writer, condition_type_str);
	if (ret) {
		goto mi_error;
	}

	/* Session name. */
	ret = mi_lttng_writer_write_element_string(
		writer, mi_lttng_element_session_name, session_name);
	if (ret) {
		goto mi_error;
	}

	/* Channel name. */
	ret = mi_lttng_writer_write_element_string(
		writer, mi_lttng_element_condition_channel_name, channel_name);
	if (ret) {
		goto mi_error;
	}

	/* Domain. */
	ret = mi_lttng_writer_write_element_string(
		writer, config_element_domain, mi_lttng_domaintype_string(domain_type));
	if (ret) {
		goto mi_error;
	}

	if (is_threshold_bytes) {
		/* Usage in bytes. */
		ret = mi_lttng_writer_write_element_unsigned_int(
			writer, mi_lttng_element_condition_threshold_bytes, threshold_bytes);
		if (ret) {
			goto mi_error;
		}
	} else {
		/* Ratio. */
		ret = mi_lttng_writer_write_element_double(
			writer, mi_lttng_element_condition_threshold_ratio, threshold_ratio);
		if (ret) {
			goto mi_error;
		}
	}

	/* Closing sub type condition element. */
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

static struct lttng_condition *lttng_condition_buffer_usage_create(enum lttng_condition_type type)
{
	struct lttng_condition_buffer_usage *condition;

	condition = zmalloc<lttng_condition_buffer_usage>();
	if (!condition) {
		return NULL;
	}

	lttng_condition_init(&condition->parent, type);
	condition->parent.validate = lttng_condition_buffer_usage_validate;
	condition->parent.serialize = lttng_condition_buffer_usage_serialize;
	condition->parent.equal = lttng_condition_buffer_usage_is_equal;
	condition->parent.destroy = lttng_condition_buffer_usage_destroy;
	condition->parent.mi_serialize = lttng_condition_buffer_usage_mi_serialize;
	return &condition->parent;
}

struct lttng_condition *lttng_condition_buffer_usage_low_create(void)
{
	return lttng_condition_buffer_usage_create(LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW);
}

struct lttng_condition *lttng_condition_buffer_usage_high_create(void)
{
	return lttng_condition_buffer_usage_create(LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH);
}

static ssize_t init_condition_from_payload(struct lttng_condition *condition,
					   struct lttng_payload_view *src_view)
{
	ssize_t ret, condition_size;
	enum lttng_condition_status status;
	enum lttng_domain_type domain_type;
	const char *session_name, *channel_name;
	struct lttng_buffer_view names_view;
	const struct lttng_condition_buffer_usage_comm *condition_comm;
	const struct lttng_payload_view condition_comm_view =
		lttng_payload_view_from_view(src_view, 0, sizeof(*condition_comm));

	if (!lttng_payload_view_is_valid(&condition_comm_view)) {
		ERR("Failed to initialize from malformed condition buffer: buffer too short to contain header");
		ret = -1;
		goto end;
	}

	condition_comm = (typeof(condition_comm)) condition_comm_view.buffer.data;
	names_view = lttng_buffer_view_from_view(&src_view->buffer, sizeof(*condition_comm), -1);

	if (condition_comm->session_name_len > LTTNG_NAME_MAX ||
	    condition_comm->channel_name_len > LTTNG_NAME_MAX) {
		ERR("Failed to initialize from malformed condition buffer: name exceeds LTTNG_MAX_NAME");
		ret = -1;
		goto end;
	}

	if (names_view.size <
	    (condition_comm->session_name_len + condition_comm->channel_name_len)) {
		ERR("Failed to initialize from malformed condition buffer: buffer too short to contain element names");
		ret = -1;
		goto end;
	}

	if (condition_comm->threshold_set_in_bytes) {
		status = lttng_condition_buffer_usage_set_threshold(
			condition, condition_comm->threshold_bytes);
	} else {
		status = lttng_condition_buffer_usage_set_threshold_ratio(
			condition, condition_comm->threshold_ratio);
	}

	if (status != LTTNG_CONDITION_STATUS_OK) {
		ERR("Failed to initialize buffer usage condition threshold");
		ret = -1;
		goto end;
	}

	if (condition_comm->domain_type <= LTTNG_DOMAIN_NONE ||
	    condition_comm->domain_type > LTTNG_DOMAIN_PYTHON) {
		/* Invalid domain value. */
		ERR("Invalid domain type value (%i) found in condition buffer",
		    (int) condition_comm->domain_type);
		ret = -1;
		goto end;
	}

	domain_type = (enum lttng_domain_type) condition_comm->domain_type;
	status = lttng_condition_buffer_usage_set_domain_type(condition, domain_type);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		ERR("Failed to set buffer usage condition domain");
		ret = -1;
		goto end;
	}

	session_name = names_view.data;
	if (*(session_name + condition_comm->session_name_len - 1) != '\0') {
		ERR("Malformed session name encountered in condition buffer");
		ret = -1;
		goto end;
	}

	channel_name = session_name + condition_comm->session_name_len;
	if (*(channel_name + condition_comm->channel_name_len - 1) != '\0') {
		ERR("Malformed channel name encountered in condition buffer");
		ret = -1;
		goto end;
	}

	status = lttng_condition_buffer_usage_set_session_name(condition, session_name);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		ERR("Failed to set buffer usage session name");
		ret = -1;
		goto end;
	}

	status = lttng_condition_buffer_usage_set_channel_name(condition, channel_name);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		ERR("Failed to set buffer usage channel name");
		ret = -1;
		goto end;
	}

	if (!lttng_condition_validate(condition)) {
		ret = -1;
		goto end;
	}

	condition_size = sizeof(*condition_comm) + (ssize_t) condition_comm->session_name_len +
		(ssize_t) condition_comm->channel_name_len;
	ret = condition_size;
end:
	return ret;
}

ssize_t lttng_condition_buffer_usage_low_create_from_payload(struct lttng_payload_view *view,
							     struct lttng_condition **_condition)
{
	ssize_t ret;
	struct lttng_condition *condition = lttng_condition_buffer_usage_low_create();

	if (!_condition || !condition) {
		ret = -1;
		goto error;
	}

	ret = init_condition_from_payload(condition, view);
	if (ret < 0) {
		goto error;
	}

	*_condition = condition;
	return ret;
error:
	lttng_condition_destroy(condition);
	return ret;
}

ssize_t lttng_condition_buffer_usage_high_create_from_payload(struct lttng_payload_view *view,
							      struct lttng_condition **_condition)
{
	ssize_t ret;
	struct lttng_condition *condition = lttng_condition_buffer_usage_high_create();

	if (!_condition || !condition) {
		ret = -1;
		goto error;
	}

	ret = init_condition_from_payload(condition, view);
	if (ret < 0) {
		goto error;
	}

	*_condition = condition;
	return ret;
error:
	lttng_condition_destroy(condition);
	return ret;
}

static struct lttng_evaluation *create_evaluation_from_payload(enum lttng_condition_type type,
							       struct lttng_payload_view *view)
{
	const struct lttng_evaluation_buffer_usage_comm *comm = (typeof(comm)) view->buffer.data;
	struct lttng_evaluation *evaluation = NULL;

	if (view->buffer.size < sizeof(*comm)) {
		goto end;
	}

	evaluation =
		lttng_evaluation_buffer_usage_create(type, comm->buffer_use, comm->buffer_capacity);
end:
	return evaluation;
}

ssize_t lttng_evaluation_buffer_usage_low_create_from_payload(struct lttng_payload_view *view,
							      struct lttng_evaluation **_evaluation)
{
	ssize_t ret;
	struct lttng_evaluation *evaluation = NULL;

	if (!_evaluation) {
		ret = -1;
		goto error;
	}

	evaluation = create_evaluation_from_payload(LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW, view);
	if (!evaluation) {
		ret = -1;
		goto error;
	}

	*_evaluation = evaluation;
	ret = sizeof(struct lttng_evaluation_buffer_usage_comm);
	return ret;
error:
	lttng_evaluation_destroy(evaluation);
	return ret;
}

ssize_t
lttng_evaluation_buffer_usage_high_create_from_payload(struct lttng_payload_view *view,
						       struct lttng_evaluation **_evaluation)
{
	ssize_t ret;
	struct lttng_evaluation *evaluation = NULL;

	if (!_evaluation) {
		ret = -1;
		goto error;
	}

	evaluation = create_evaluation_from_payload(LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH, view);
	if (!evaluation) {
		ret = -1;
		goto error;
	}

	*_evaluation = evaluation;
	ret = sizeof(struct lttng_evaluation_buffer_usage_comm);
	return ret;
error:
	lttng_evaluation_destroy(evaluation);
	return ret;
}

enum lttng_condition_status
lttng_condition_buffer_usage_get_threshold_ratio(const struct lttng_condition *condition,
						 double *threshold_ratio)
{
	struct lttng_condition_buffer_usage *usage;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_USAGE_CONDITION(condition) || !threshold_ratio) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	usage = lttng::utils::container_of(condition, &lttng_condition_buffer_usage::parent);
	if (!usage->threshold_ratio.set) {
		status = LTTNG_CONDITION_STATUS_UNSET;
		goto end;
	}
	*threshold_ratio = usage->threshold_ratio.value;
end:
	return status;
}

/* threshold_ratio expressed as [0.0, 1.0]. */
enum lttng_condition_status
lttng_condition_buffer_usage_set_threshold_ratio(struct lttng_condition *condition,
						 double threshold_ratio)
{
	struct lttng_condition_buffer_usage *usage;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_USAGE_CONDITION(condition) || threshold_ratio < 0.0 ||
	    threshold_ratio > 1.0) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	usage = lttng::utils::container_of(condition, &lttng_condition_buffer_usage::parent);
	usage->threshold_ratio.set = true;
	usage->threshold_bytes.set = false;
	usage->threshold_ratio.value = threshold_ratio;
end:
	return status;
}

enum lttng_condition_status
lttng_condition_buffer_usage_get_threshold(const struct lttng_condition *condition,
					   uint64_t *threshold_bytes)
{
	struct lttng_condition_buffer_usage *usage;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_USAGE_CONDITION(condition) || !threshold_bytes) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	usage = lttng::utils::container_of(condition, &lttng_condition_buffer_usage::parent);
	if (!usage->threshold_bytes.set) {
		status = LTTNG_CONDITION_STATUS_UNSET;
		goto end;
	}
	*threshold_bytes = usage->threshold_bytes.value;
end:
	return status;
}

enum lttng_condition_status
lttng_condition_buffer_usage_set_threshold(struct lttng_condition *condition,
					   uint64_t threshold_bytes)
{
	struct lttng_condition_buffer_usage *usage;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_USAGE_CONDITION(condition)) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	usage = lttng::utils::container_of(condition, &lttng_condition_buffer_usage::parent);
	usage->threshold_ratio.set = false;
	usage->threshold_bytes.set = true;
	usage->threshold_bytes.value = threshold_bytes;
end:
	return status;
}

enum lttng_condition_status
lttng_condition_buffer_usage_get_session_name(const struct lttng_condition *condition,
					      const char **session_name)
{
	struct lttng_condition_buffer_usage *usage;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_USAGE_CONDITION(condition) || !session_name) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	usage = lttng::utils::container_of(condition, &lttng_condition_buffer_usage::parent);
	if (!usage->session_name) {
		status = LTTNG_CONDITION_STATUS_UNSET;
		goto end;
	}
	*session_name = usage->session_name;
end:
	return status;
}

enum lttng_condition_status
lttng_condition_buffer_usage_set_session_name(struct lttng_condition *condition,
					      const char *session_name)
{
	char *session_name_copy;
	struct lttng_condition_buffer_usage *usage;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_USAGE_CONDITION(condition) || !session_name ||
	    strlen(session_name) == 0) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	usage = lttng::utils::container_of(condition, &lttng_condition_buffer_usage::parent);
	session_name_copy = strdup(session_name);
	if (!session_name_copy) {
		status = LTTNG_CONDITION_STATUS_ERROR;
		goto end;
	}

	if (usage->session_name) {
		free(usage->session_name);
	}
	usage->session_name = session_name_copy;
end:
	return status;
}

enum lttng_condition_status
lttng_condition_buffer_usage_get_channel_name(const struct lttng_condition *condition,
					      const char **channel_name)
{
	struct lttng_condition_buffer_usage *usage;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_USAGE_CONDITION(condition) || !channel_name) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	usage = lttng::utils::container_of(condition, &lttng_condition_buffer_usage::parent);
	if (!usage->channel_name) {
		status = LTTNG_CONDITION_STATUS_UNSET;
		goto end;
	}
	*channel_name = usage->channel_name;
end:
	return status;
}

enum lttng_condition_status
lttng_condition_buffer_usage_set_channel_name(struct lttng_condition *condition,
					      const char *channel_name)
{
	char *channel_name_copy;
	struct lttng_condition_buffer_usage *usage;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_USAGE_CONDITION(condition) || !channel_name ||
	    strlen(channel_name) == 0) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	usage = lttng::utils::container_of(condition, &lttng_condition_buffer_usage::parent);
	channel_name_copy = strdup(channel_name);
	if (!channel_name_copy) {
		status = LTTNG_CONDITION_STATUS_ERROR;
		goto end;
	}

	if (usage->channel_name) {
		free(usage->channel_name);
	}
	usage->channel_name = channel_name_copy;
end:
	return status;
}

enum lttng_condition_status
lttng_condition_buffer_usage_get_domain_type(const struct lttng_condition *condition,
					     enum lttng_domain_type *type)
{
	struct lttng_condition_buffer_usage *usage;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_USAGE_CONDITION(condition) || !type) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	usage = lttng::utils::container_of(condition, &lttng_condition_buffer_usage::parent);
	if (!usage->domain.set) {
		status = LTTNG_CONDITION_STATUS_UNSET;
		goto end;
	}
	*type = usage->domain.type;
end:
	return status;
}

enum lttng_condition_status
lttng_condition_buffer_usage_set_domain_type(struct lttng_condition *condition,
					     enum lttng_domain_type type)
{
	struct lttng_condition_buffer_usage *usage;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_USAGE_CONDITION(condition) || type == LTTNG_DOMAIN_NONE) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	usage = lttng::utils::container_of(condition, &lttng_condition_buffer_usage::parent);
	usage->domain.set = true;
	usage->domain.type = type;
end:
	return status;
}

static int lttng_evaluation_buffer_usage_serialize(const struct lttng_evaluation *evaluation,
						   struct lttng_payload *payload)
{
	struct lttng_evaluation_buffer_usage *usage;
	struct lttng_evaluation_buffer_usage_comm comm;

	usage = lttng::utils::container_of(evaluation, &lttng_evaluation_buffer_usage::parent);
	comm.buffer_use = usage->buffer_use;
	comm.buffer_capacity = usage->buffer_capacity;

	return lttng_dynamic_buffer_append(&payload->buffer, &comm, sizeof(comm));
}

static void lttng_evaluation_buffer_usage_destroy(struct lttng_evaluation *evaluation)
{
	struct lttng_evaluation_buffer_usage *usage;

	usage = lttng::utils::container_of(evaluation, &lttng_evaluation_buffer_usage::parent);
	free(usage);
}

struct lttng_evaluation *lttng_evaluation_buffer_usage_create(enum lttng_condition_type type,
							      uint64_t use,
							      uint64_t capacity)
{
	struct lttng_evaluation_buffer_usage *usage;

	usage = zmalloc<lttng_evaluation_buffer_usage>();
	if (!usage) {
		goto end;
	}

	usage->parent.type = type;
	usage->buffer_use = use;
	usage->buffer_capacity = capacity;
	usage->parent.serialize = lttng_evaluation_buffer_usage_serialize;
	usage->parent.destroy = lttng_evaluation_buffer_usage_destroy;
end:
	return &usage->parent;
}

/*
 * Get the sampled buffer usage which caused the associated condition to
 * evaluate to "true".
 */
enum lttng_evaluation_status
lttng_evaluation_buffer_usage_get_usage_ratio(const struct lttng_evaluation *evaluation,
					      double *usage_ratio)
{
	struct lttng_evaluation_buffer_usage *usage;
	enum lttng_evaluation_status status = LTTNG_EVALUATION_STATUS_OK;

	if (!evaluation || !is_usage_evaluation(evaluation) || !usage_ratio) {
		status = LTTNG_EVALUATION_STATUS_INVALID;
		goto end;
	}

	usage = lttng::utils::container_of(evaluation, &lttng_evaluation_buffer_usage::parent);
	*usage_ratio = (double) usage->buffer_use / (double) usage->buffer_capacity;
end:
	return status;
}

enum lttng_evaluation_status
lttng_evaluation_buffer_usage_get_usage(const struct lttng_evaluation *evaluation,
					uint64_t *usage_bytes)
{
	struct lttng_evaluation_buffer_usage *usage;
	enum lttng_evaluation_status status = LTTNG_EVALUATION_STATUS_OK;

	if (!evaluation || !is_usage_evaluation(evaluation) || !usage_bytes) {
		status = LTTNG_EVALUATION_STATUS_INVALID;
		goto end;
	}

	usage = lttng::utils::container_of(evaluation, &lttng_evaluation_buffer_usage::parent);
	*usage_bytes = usage->buffer_use;
end:
	return status;
}
