/*
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <lttng/condition/condition-internal.h>
#include <lttng/condition/buffer-usage-internal.h>
#include <common/macros.h>
#include <common/error.h>
#include <assert.h>
#include <math.h>
#include <float.h>
#include <time.h>

#define IS_USAGE_CONDITION(condition) ( \
	lttng_condition_get_type(condition) == LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW || \
	lttng_condition_get_type(condition) == LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH   \
	)

static
double fixed_to_double(uint32_t val)
{
	return (double) val / (double) UINT32_MAX;
}

static
uint64_t double_to_fixed(double val)
{
	return (val * (double) UINT32_MAX);
}

static
bool is_usage_evaluation(const struct lttng_evaluation *evaluation)
{
	enum lttng_condition_type type = lttng_evaluation_get_type(evaluation);

	return type == LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW ||
			type == LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH;
}

static
void lttng_condition_buffer_usage_destroy(struct lttng_condition *condition)
{
	struct lttng_condition_buffer_usage *usage;

	usage = container_of(condition, struct lttng_condition_buffer_usage,
			parent);

	free(usage->session_name);
	free(usage->channel_name);
	free(usage);
}

static
bool lttng_condition_buffer_usage_validate(
		const struct lttng_condition *condition)
{
	bool valid = false;
	struct lttng_condition_buffer_usage *usage;

	if (!condition) {
		goto end;
	}

	usage = container_of(condition, struct lttng_condition_buffer_usage,
			parent);
	if (!usage->session_name) {
		ERR("Invalid buffer condition: a target session name must be set.");
		goto end;
	}
	if (!usage->channel_name) {
		ERR("Invalid buffer condition: a target channel name must be set.");
		goto end;
	}
	if (!usage->threshold_ratio.set && !usage->threshold_bytes.set) {
		ERR("Invalid buffer condition: a threshold must be set.");
		goto end;
	}

	valid = true;
end:
	return valid;
}

static
ssize_t lttng_condition_buffer_usage_serialize(
		const struct lttng_condition *condition, char *buf)
{
	struct lttng_condition_buffer_usage *usage;
	ssize_t ret, size;
	size_t session_name_len, channel_name_len;

	if (!condition || !IS_USAGE_CONDITION(condition)) {
		ret = -1;
		goto end;
	}

	DBG("Serializing buffer usage condition");
	usage = container_of(condition, struct lttng_condition_buffer_usage,
			parent);
	size = sizeof(struct lttng_condition_buffer_usage_comm);
	session_name_len = strlen(usage->session_name) + 1;
	channel_name_len = strlen(usage->channel_name) + 1;
	if (session_name_len > LTTNG_NAME_MAX ||
			channel_name_len > LTTNG_NAME_MAX) {
		ret = -1;
		goto end;
	}
	size += session_name_len + channel_name_len;
	if (buf) {
		struct lttng_condition_buffer_usage_comm usage_comm = {
			.threshold_set_in_bytes = usage->threshold_bytes.set ? 1 : 0,
			.session_name_len = session_name_len,
			.channel_name_len = channel_name_len,
			.domain_type = (int8_t) usage->domain.type,
		};

		if (usage->threshold_bytes.set) {
			usage_comm.threshold = usage->threshold_bytes.value;
		} else {
			uint64_t val = double_to_fixed(
					usage->threshold_ratio.value);

			if (val > UINT32_MAX) {
				/* overflow. */
				ret = -1;
				goto end;
			}
			usage_comm.threshold = val;
		}

		memcpy(buf, &usage_comm, sizeof(usage_comm));
		buf += sizeof(usage_comm);
		memcpy(buf, usage->session_name, session_name_len);
		buf += session_name_len;
		memcpy(buf, usage->channel_name, channel_name_len);
	}
	ret = size;
end:
	return ret;
}

static
bool lttng_condition_buffer_usage_is_equal(const struct lttng_condition *_a,
		const struct lttng_condition *_b)
{
	bool is_equal = false;
	struct lttng_condition_buffer_usage *a, *b;

	a = container_of(_a, struct lttng_condition_buffer_usage, parent);
	b = container_of(_b, struct lttng_condition_buffer_usage, parent);

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

	if ((a->session_name && !b->session_name) ||
			(!a->session_name && b->session_name)) {
		goto end;
	}

	if (a->channel_name && b->channel_name) {
		if (strcmp(a->channel_name, b->channel_name)) {
			goto end;
		}
	}	if ((a->channel_name && !b->channel_name) ||
			(!a->channel_name && b->channel_name)) {
		goto end;
	}

	if (a->channel_name && b->channel_name) {
		if (strcmp(a->channel_name, b->channel_name)) {
			goto end;
		}
	}

	if ((a->domain.set && !b->domain.set) ||
			(!a->domain.set && b->domain.set)) {
		goto end;
	}

	if (a->domain.set && b->domain.set) {
		if (a->domain.type != b->domain.type) {
			goto end;
		}
	}
	is_equal = true;
end:
	return is_equal;
}

static
struct lttng_condition *lttng_condition_buffer_usage_create(
		enum lttng_condition_type type)
{
	struct lttng_condition_buffer_usage *condition;

	condition = zmalloc(sizeof(struct lttng_condition_buffer_usage));
	if (!condition) {
		return NULL;
	}

	lttng_condition_init(&condition->parent, type);
	condition->parent.validate = lttng_condition_buffer_usage_validate;
	condition->parent.serialize = lttng_condition_buffer_usage_serialize;
	condition->parent.equal = lttng_condition_buffer_usage_is_equal;
	condition->parent.destroy = lttng_condition_buffer_usage_destroy;
	return &condition->parent;
}

struct lttng_condition *lttng_condition_buffer_usage_low_create(void)
{
	return lttng_condition_buffer_usage_create(
			LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW);
}

struct lttng_condition *lttng_condition_buffer_usage_high_create(void)
{
	return lttng_condition_buffer_usage_create(
			LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH);
}

static
ssize_t init_condition_from_buffer(struct lttng_condition *condition,
		const struct lttng_buffer_view *src_view)
{
	ssize_t ret, condition_size;
	enum lttng_condition_status status;
	enum lttng_domain_type domain_type;
	const struct lttng_condition_buffer_usage_comm *condition_comm;
	const char *session_name, *channel_name;
	struct lttng_buffer_view names_view;

	if (src_view->size < sizeof(*condition_comm)) {
		ERR("Failed to initialize from malformed condition buffer: buffer too short to contain header");
		ret = -1;
		goto end;
	}

	condition_comm = (const struct lttng_condition_buffer_usage_comm *) src_view->data;
	names_view = lttng_buffer_view_from_view(src_view,
			sizeof(*condition_comm), -1);

	if (condition_comm->session_name_len > LTTNG_NAME_MAX ||
			condition_comm->channel_name_len > LTTNG_NAME_MAX) {
		ERR("Failed to initialize from malformed condition buffer: name exceeds LTTNG_MAX_NAME");
		ret = -1;
		goto end;
	}

	if (names_view.size <
			(condition_comm->session_name_len +
			condition_comm->channel_name_len)) {
		ERR("Failed to initialize from malformed condition buffer: buffer too short to contain element names");
		ret = -1;
		goto end;
	}

	if (condition_comm->threshold_set_in_bytes) {
		status = lttng_condition_buffer_usage_set_threshold(condition,
				condition_comm->threshold);
	} else {
		status = lttng_condition_buffer_usage_set_threshold_ratio(
				condition,
				fixed_to_double(condition_comm->threshold));
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
	status = lttng_condition_buffer_usage_set_domain_type(condition,
			domain_type);
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

	status = lttng_condition_buffer_usage_set_session_name(condition,
			session_name);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		ERR("Failed to set buffer usage session name");
		ret = -1;
		goto end;
	}

	status = lttng_condition_buffer_usage_set_channel_name(condition,
			channel_name);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		ERR("Failed to set buffer usage channel name");
		ret = -1;
		goto end;
	}

	if (!lttng_condition_validate(condition)) {
		ret = -1;
		goto end;
	}

	condition_size = sizeof(*condition_comm) +
			(ssize_t) condition_comm->session_name_len +
			(ssize_t) condition_comm->channel_name_len;
	ret = condition_size;
end:
	return ret;
}

LTTNG_HIDDEN
ssize_t lttng_condition_buffer_usage_low_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_condition **_condition)
{
	ssize_t ret;
	struct lttng_condition *condition =
			lttng_condition_buffer_usage_low_create();

	if (!_condition || !condition) {
		ret = -1;
		goto error;
	}

	ret = init_condition_from_buffer(condition, view);
	if (ret < 0) {
		goto error;
	}

	*_condition = condition;
	return ret;
error:
	lttng_condition_destroy(condition);
	return ret;
}

LTTNG_HIDDEN
ssize_t lttng_condition_buffer_usage_high_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_condition **_condition)
{
	ssize_t ret;
	struct lttng_condition *condition =
			lttng_condition_buffer_usage_high_create();

	if (!_condition || !condition) {
		ret = -1;
		goto error;
	}

	ret = init_condition_from_buffer(condition, view);
	if (ret < 0) {
		goto error;
	}

	*_condition = condition;
	return ret;
error:
	lttng_condition_destroy(condition);
	return ret;
}

static
struct lttng_evaluation *create_evaluation_from_buffer(
		enum lttng_condition_type type,
		const struct lttng_buffer_view *view)
{
	const struct lttng_evaluation_buffer_usage_comm *comm =
			(const struct lttng_evaluation_buffer_usage_comm *) view->data;
	struct lttng_evaluation *evaluation = NULL;

	if (view->size < sizeof(*comm)) {
		goto end;
	}

	evaluation = lttng_evaluation_buffer_usage_create(type,
			comm->buffer_use, comm->buffer_capacity);
end:
	return evaluation;
}

LTTNG_HIDDEN
ssize_t lttng_evaluation_buffer_usage_low_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_evaluation **_evaluation)
{
	ssize_t ret;
	struct lttng_evaluation *evaluation = NULL;

	if (!_evaluation) {
		ret = -1;
		goto error;
	}

	evaluation = create_evaluation_from_buffer(
			LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW, view);
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

LTTNG_HIDDEN
ssize_t lttng_evaluation_buffer_usage_high_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_evaluation **_evaluation)
{
	ssize_t ret;
	struct lttng_evaluation *evaluation = NULL;

	if (!_evaluation) {
		ret = -1;
		goto error;
	}

	evaluation = create_evaluation_from_buffer(
			LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH, view);
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
lttng_condition_buffer_usage_get_threshold_ratio(
		const struct lttng_condition *condition,
		double *threshold_ratio)
{
	struct lttng_condition_buffer_usage *usage;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_USAGE_CONDITION(condition) ||
			!threshold_ratio) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	usage = container_of(condition, struct lttng_condition_buffer_usage,
			parent);
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
lttng_condition_buffer_usage_set_threshold_ratio(
		struct lttng_condition *condition, double threshold_ratio)
{
	struct lttng_condition_buffer_usage *usage;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_USAGE_CONDITION(condition) ||
			threshold_ratio < 0.0 ||
			threshold_ratio > 1.0) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	usage = container_of(condition, struct lttng_condition_buffer_usage,
			parent);
	usage->threshold_ratio.set = true;
	usage->threshold_bytes.set = false;
	usage->threshold_ratio.value = threshold_ratio;
end:
	return status;
}

enum lttng_condition_status
lttng_condition_buffer_usage_get_threshold(
		const struct lttng_condition *condition,
		uint64_t *threshold_bytes)
{
	struct lttng_condition_buffer_usage *usage;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_USAGE_CONDITION(condition) || !threshold_bytes) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	usage = container_of(condition, struct lttng_condition_buffer_usage,
			parent);
	if (!usage->threshold_bytes.set) {
		status = LTTNG_CONDITION_STATUS_UNSET;
		goto end;
	}
	*threshold_bytes = usage->threshold_bytes.value;
end:
	return status;
}

enum lttng_condition_status
lttng_condition_buffer_usage_set_threshold(
		struct lttng_condition *condition, uint64_t threshold_bytes)
{
	struct lttng_condition_buffer_usage *usage;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_USAGE_CONDITION(condition)) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	usage = container_of(condition, struct lttng_condition_buffer_usage,
			parent);
	usage->threshold_ratio.set = false;
	usage->threshold_bytes.set = true;
	usage->threshold_bytes.value = threshold_bytes;
end:
	return status;
}

enum lttng_condition_status
lttng_condition_buffer_usage_get_session_name(
		const struct lttng_condition *condition,
		const char **session_name)
{
	struct lttng_condition_buffer_usage *usage;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_USAGE_CONDITION(condition) || !session_name) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	usage = container_of(condition, struct lttng_condition_buffer_usage,
			parent);
	if (!usage->session_name) {
		status = LTTNG_CONDITION_STATUS_UNSET;
		goto end;
	}
	*session_name = usage->session_name;
end:
	return status;
}

enum lttng_condition_status
lttng_condition_buffer_usage_set_session_name(
		struct lttng_condition *condition, const char *session_name)
{
	char *session_name_copy;
	struct lttng_condition_buffer_usage *usage;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_USAGE_CONDITION(condition) || !session_name ||
			strlen(session_name) == 0) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	usage = container_of(condition, struct lttng_condition_buffer_usage,
			parent);
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
lttng_condition_buffer_usage_get_channel_name(
		const struct lttng_condition *condition,
		const char **channel_name)
{
	struct lttng_condition_buffer_usage *usage;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_USAGE_CONDITION(condition) || !channel_name) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	usage = container_of(condition, struct lttng_condition_buffer_usage,
			parent);
	if (!usage->channel_name) {
		status = LTTNG_CONDITION_STATUS_UNSET;
		goto end;
	}
	*channel_name = usage->channel_name;
end:
	return status;
}

enum lttng_condition_status
lttng_condition_buffer_usage_set_channel_name(
		struct lttng_condition *condition, const char *channel_name)
{
	char *channel_name_copy;
	struct lttng_condition_buffer_usage *usage;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_USAGE_CONDITION(condition) || !channel_name ||
			strlen(channel_name) == 0) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	usage = container_of(condition, struct lttng_condition_buffer_usage,
			parent);
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
lttng_condition_buffer_usage_get_domain_type(
		const struct lttng_condition *condition,
		enum lttng_domain_type *type)
{
	struct lttng_condition_buffer_usage *usage;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_USAGE_CONDITION(condition) || !type) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	usage = container_of(condition, struct lttng_condition_buffer_usage,
			parent);
	if (!usage->domain.set) {
		status = LTTNG_CONDITION_STATUS_UNSET;
		goto end;
	}
	*type = usage->domain.type;
end:
	return status;
}

enum lttng_condition_status
lttng_condition_buffer_usage_set_domain_type(
		struct lttng_condition *condition, enum lttng_domain_type type)
{
	struct lttng_condition_buffer_usage *usage;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_USAGE_CONDITION(condition) ||
			type == LTTNG_DOMAIN_NONE) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	usage = container_of(condition, struct lttng_condition_buffer_usage,
			parent);
	usage->domain.set = true;
	usage->domain.type = type;
end:
	return status;
}

static
ssize_t lttng_evaluation_buffer_usage_serialize(
		struct lttng_evaluation *evaluation, char *buf)
{
	ssize_t ret;
	struct lttng_evaluation_buffer_usage *usage;

	usage = container_of(evaluation, struct lttng_evaluation_buffer_usage,
			parent);
	if (buf) {
		struct lttng_evaluation_buffer_usage_comm comm = {
			.buffer_use = usage->buffer_use,
			.buffer_capacity = usage->buffer_capacity,
		};

		memcpy(buf, &comm, sizeof(comm));
	}

	ret = sizeof(struct lttng_evaluation_buffer_usage_comm);
	return ret;
}

static
void lttng_evaluation_buffer_usage_destroy(
		struct lttng_evaluation *evaluation)
{
	struct lttng_evaluation_buffer_usage *usage;

	usage = container_of(evaluation, struct lttng_evaluation_buffer_usage,
			parent);
	free(usage);
}

LTTNG_HIDDEN
struct lttng_evaluation *lttng_evaluation_buffer_usage_create(
		enum lttng_condition_type type, uint64_t use, uint64_t capacity)
{
	struct lttng_evaluation_buffer_usage *usage;

	usage = zmalloc(sizeof(struct lttng_evaluation_buffer_usage));
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
lttng_evaluation_buffer_usage_get_usage_ratio(
		const struct lttng_evaluation *evaluation, double *usage_ratio)
{
	struct lttng_evaluation_buffer_usage *usage;
	enum lttng_evaluation_status status = LTTNG_EVALUATION_STATUS_OK;

	if (!evaluation || !is_usage_evaluation(evaluation) || !usage_ratio) {
		status = LTTNG_EVALUATION_STATUS_INVALID;
		goto end;
	}

	usage = container_of(evaluation, struct lttng_evaluation_buffer_usage,
			parent);
	*usage_ratio = (double) usage->buffer_use /
			(double) usage->buffer_capacity;
end:
	return status;
}

enum lttng_evaluation_status
lttng_evaluation_buffer_usage_get_usage(
		const struct lttng_evaluation *evaluation,
		uint64_t *usage_bytes)
{
	struct lttng_evaluation_buffer_usage *usage;
	enum lttng_evaluation_status status = LTTNG_EVALUATION_STATUS_OK;

	if (!evaluation || !is_usage_evaluation(evaluation) || !usage_bytes) {
		status = LTTNG_EVALUATION_STATUS_INVALID;
		goto end;
	}

	usage = container_of(evaluation, struct lttng_evaluation_buffer_usage,
			parent);
	*usage_bytes = usage->buffer_use;
end:
	return status;
}
