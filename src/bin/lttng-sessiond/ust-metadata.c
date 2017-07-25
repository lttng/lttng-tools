/*
 * ust-metadata.c
 *
 * LTTng-UST metadata generation
 *
 * Copyright (C) 2010-2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <inttypes.h>
#include <common/common.h>
#include <common/time.h>

#include "ust-registry.h"
#include "ust-clock.h"
#include "ust-app.h"

#ifndef max_t
#define max_t(type, a, b)	((type) ((a) > (b) ? (a) : (b)))
#endif

#define NR_CLOCK_OFFSET_SAMPLES		10

struct offset_sample {
	int64_t offset;			/* correlation offset */
	uint64_t measure_delta;		/* lower is better */
};

static
int _lttng_field_statedump(struct ust_registry_session *session,
		const struct ustctl_field *fields, size_t nr_fields,
		size_t *iter_field, size_t nesting);

static inline
int fls(unsigned int x)
{
	int r = 32;

	if (!x)
		return 0;
	if (!(x & 0xFFFF0000U)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xFF000000U)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xF0000000U)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xC0000000U)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000U)) {
		r -= 1;
	}
	return r;
}

static inline
int get_count_order(unsigned int count)
{
	int order;

	order = fls(count) - 1;
	if (count & (count - 1))
		order++;
	return order;
}

/*
 * Returns offset where to write in metadata array, or negative error value on error.
 */
static
ssize_t metadata_reserve(struct ust_registry_session *session, size_t len)
{
	size_t new_len = session->metadata_len + len;
	size_t new_alloc_len = new_len;
	size_t old_alloc_len = session->metadata_alloc_len;
	ssize_t ret;

	if (new_alloc_len > (UINT32_MAX >> 1))
		return -EINVAL;
	if ((old_alloc_len << 1) > (UINT32_MAX >> 1))
		return -EINVAL;

	if (new_alloc_len > old_alloc_len) {
		char *newptr;

		new_alloc_len =
			max_t(size_t, 1U << get_count_order(new_alloc_len), old_alloc_len << 1);
		newptr = realloc(session->metadata, new_alloc_len);
		if (!newptr)
			return -ENOMEM;
		session->metadata = newptr;
		/* We zero directly the memory from start of allocation. */
		memset(&session->metadata[old_alloc_len], 0, new_alloc_len - old_alloc_len);
		session->metadata_alloc_len = new_alloc_len;
	}
	ret = session->metadata_len;
	session->metadata_len += len;
	return ret;
}

static
int metadata_file_append(struct ust_registry_session *session,
		const char *str, size_t len)
{
	ssize_t written;

	if (session->metadata_fd < 0) {
		return 0;
	}
	/* Write to metadata file */
	written = lttng_write(session->metadata_fd, str, len);
	if (written != len) {
		return -1;
	}
	return 0;
}

/*
 * We have exclusive access to our metadata buffer (protected by the
 * ust_lock), so we can do racy operations such as looking for
 * remaining space left in packet and write, since mutual exclusion
 * protects us from concurrent writes.
 */
static
int lttng_metadata_printf(struct ust_registry_session *session,
		const char *fmt, ...)
{
	char *str = NULL;
	size_t len;
	va_list ap;
	ssize_t offset;
	int ret;

	va_start(ap, fmt);
	ret = vasprintf(&str, fmt, ap);
	va_end(ap);
	if (ret < 0)
		return -ENOMEM;

	len = strlen(str);
	offset = metadata_reserve(session, len);
	if (offset < 0) {
		ret = offset;
		goto end;
	}
	memcpy(&session->metadata[offset], str, len);
	ret = metadata_file_append(session, str, len);
	if (ret) {
		PERROR("Error appending to metadata file");
		goto end;
	}
	DBG3("Append to metadata: \"%s\"", str);
	ret = 0;

end:
	free(str);
	return ret;
}

static
int print_tabs(struct ust_registry_session *session, size_t nesting)
{
	size_t i;

	for (i = 0; i < nesting; i++) {
		int ret;

		ret = lttng_metadata_printf(session, "	");
		if (ret) {
			return ret;
		}
	}
	return 0;
}

static
void sanitize_ctf_identifier(char *out, const char *in)
{
	size_t i;

	for (i = 0; i < LTTNG_UST_SYM_NAME_LEN; i++) {
		switch (in[i]) {
		case '.':
		case '$':
		case ':':
			out[i] = '_';
			break;
		default:
			out[i] = in[i];
		}
	}
}

/* Called with session registry mutex held. */
static
int ust_metadata_enum_statedump(struct ust_registry_session *session,
		const char *enum_name,
		uint64_t enum_id,
		const struct ustctl_integer_type *container_type,
		const char *field_name, size_t *iter_field, size_t nesting)
{
	struct ust_registry_enum *reg_enum;
	const struct ustctl_enum_entry *entries;
	size_t nr_entries;
	int ret = 0;
	size_t i;
	char identifier[LTTNG_UST_SYM_NAME_LEN];

	rcu_read_lock();
	reg_enum = ust_registry_lookup_enum_by_id(session, enum_name, enum_id);
	rcu_read_unlock();
	/* reg_enum can still be used because session registry mutex is held. */
	if (!reg_enum) {
		ret = -ENOENT;
		goto end;
	}
	entries = reg_enum->entries;
	nr_entries = reg_enum->nr_entries;

	ret = print_tabs(session, nesting);
	if (ret) {
		goto end;
	}
	ret = lttng_metadata_printf(session,
		"enum : integer { size = %u; align = %u; signed = %u; encoding = %s; base = %u; } {\n",
		container_type->size,
		container_type->alignment,
		container_type->signedness,
		(container_type->encoding == ustctl_encode_none)
			? "none"
			: (container_type->encoding == ustctl_encode_UTF8)
				? "UTF8"
				: "ASCII",
		container_type->base);
	if (ret) {
	        goto end;
	}
	nesting++;
	/* Dump all entries */
	for (i = 0; i < nr_entries; i++) {
		const struct ustctl_enum_entry *entry = &entries[i];
		int j, len;

		ret = print_tabs(session, nesting);
		if (ret) {
			goto end;
		}
		ret = lttng_metadata_printf(session,
				"\"");
		if (ret) {
			goto end;
		}
		len = strlen(entry->string);
		/* Escape the character '"' */
		for (j = 0; j < len; j++) {
			char c = entry->string[j];

			switch (c) {
			case '"':
				ret = lttng_metadata_printf(session,
						"\\\"");
				break;
			case '\\':
				ret = lttng_metadata_printf(session,
						"\\\\");
				break;
			default:
				ret = lttng_metadata_printf(session,
						"%c", c);
				break;
			}
			if (ret) {
				goto end;
			}
		}
		ret = lttng_metadata_printf(session, "\"");
		if (ret) {
			goto end;
		}

		if (entry->u.extra.options &
				USTCTL_UST_ENUM_ENTRY_OPTION_IS_AUTO) {
			ret = lttng_metadata_printf(session, ",\n");
			if (ret) {
				goto end;
			}
		} else {
			ret = lttng_metadata_printf(session,
					" = ");
			if (ret) {
				goto end;
			}

			if (entry->start.signedness) {
				ret = lttng_metadata_printf(session,
					"%lld", (long long) entry->start.value);
			} else {
				ret = lttng_metadata_printf(session,
					"%llu", entry->start.value);
			}
			if (ret) {
				goto end;
			}

			if (entry->start.signedness == entry->end.signedness &&
					entry->start.value ==
						entry->end.value) {
				ret = lttng_metadata_printf(session, ",\n");
			} else {
				if (entry->end.signedness) {
					ret = lttng_metadata_printf(session,
						" ... %lld,\n",
						(long long) entry->end.value);
				} else {
					ret = lttng_metadata_printf(session,
						" ... %llu,\n",
						entry->end.value);
				}
			}
			if (ret) {
				goto end;
			}
		}
	}
	nesting--;
	sanitize_ctf_identifier(identifier, field_name);
	ret = print_tabs(session, nesting);
	if (ret) {
		goto end;
	}
	ret = lttng_metadata_printf(session, "} _%s;\n",
			identifier);
end:
	(*iter_field)++;
	return ret;
}

static
int _lttng_variant_statedump(struct ust_registry_session *session,
		const struct ustctl_field *fields, size_t nr_fields,
		size_t *iter_field, size_t nesting)
{
	const struct ustctl_field *variant = &fields[*iter_field];
	uint32_t nr_choices, i;
	int ret;
	char identifier[LTTNG_UST_SYM_NAME_LEN];

	if (variant->type.atype != ustctl_atype_variant) {
		ret = -EINVAL;
		goto end;
	}
	nr_choices = variant->type.u.variant.nr_choices;
	(*iter_field)++;
	sanitize_ctf_identifier(identifier, variant->type.u.variant.tag_name);
	ret = print_tabs(session, nesting);
	if (ret) {
		goto end;
	}
	ret = lttng_metadata_printf(session,
			"variant <_%s> {\n",
			identifier);
	if (ret) {
		goto end;
	}

	for (i = 0; i < nr_choices; i++) {
		if (*iter_field >= nr_fields) {
			ret = -EOVERFLOW;
			goto end;
		}
		ret = _lttng_field_statedump(session,
				fields, nr_fields,
				iter_field, nesting + 1);
		if (ret) {
			goto end;
		}
	}
	sanitize_ctf_identifier(identifier, variant->name);
	ret = print_tabs(session, nesting);
	if (ret) {
		goto end;
	}
	ret = lttng_metadata_printf(session,
			"} _%s;\n",
			identifier);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

static
int _lttng_field_statedump(struct ust_registry_session *session,
		const struct ustctl_field *fields, size_t nr_fields,
		size_t *iter_field, size_t nesting)
{
	int ret = 0;
	const char *bo_be = " byte_order = be;";
	const char *bo_le = " byte_order = le;";
	const char *bo_native = "";
	const char *bo_reverse;
	const struct ustctl_field *field;

	if (*iter_field >= nr_fields) {
		ret = -EOVERFLOW;
		goto end;
	}
	field = &fields[*iter_field];

	if (session->byte_order == BIG_ENDIAN) {
		bo_reverse = bo_le;
	} else {
		bo_reverse = bo_be;
	}

	switch (field->type.atype) {
	case ustctl_atype_integer:
		ret = print_tabs(session, nesting);
		if (ret) {
			goto end;
		}
		ret = lttng_metadata_printf(session,
			"integer { size = %u; align = %u; signed = %u; encoding = %s; base = %u;%s } _%s;\n",
			field->type.u.basic.integer.size,
			field->type.u.basic.integer.alignment,
			field->type.u.basic.integer.signedness,
			(field->type.u.basic.integer.encoding == ustctl_encode_none)
				? "none"
				: (field->type.u.basic.integer.encoding == ustctl_encode_UTF8)
					? "UTF8"
					: "ASCII",
			field->type.u.basic.integer.base,
			field->type.u.basic.integer.reverse_byte_order ? bo_reverse : bo_native,
			field->name);
		(*iter_field)++;
		break;
	case ustctl_atype_enum:
		ret = ust_metadata_enum_statedump(session,
			field->type.u.basic.enumeration.name,
			field->type.u.basic.enumeration.id,
			&field->type.u.basic.enumeration.container_type,
			field->name, iter_field, nesting);
		break;
	case ustctl_atype_float:
		ret = print_tabs(session, nesting);
		if (ret) {
			goto end;
		}
		ret = lttng_metadata_printf(session,
			"floating_point { exp_dig = %u; mant_dig = %u; align = %u;%s } _%s;\n",
			field->type.u.basic._float.exp_dig,
			field->type.u.basic._float.mant_dig,
			field->type.u.basic._float.alignment,
			field->type.u.basic.integer.reverse_byte_order ? bo_reverse : bo_native,
			field->name);
		(*iter_field)++;
		break;
	case ustctl_atype_array:
	{
		const struct ustctl_basic_type *elem_type;

		ret = print_tabs(session, nesting);
		if (ret) {
			goto end;
		}
		elem_type = &field->type.u.array.elem_type;
		ret = lttng_metadata_printf(session,
			"integer { size = %u; align = %u; signed = %u; encoding = %s; base = %u;%s } _%s[%u];\n",
			elem_type->u.basic.integer.size,
			elem_type->u.basic.integer.alignment,
			elem_type->u.basic.integer.signedness,
			(elem_type->u.basic.integer.encoding == ustctl_encode_none)
				? "none"
				: (elem_type->u.basic.integer.encoding == ustctl_encode_UTF8)
					? "UTF8"
					: "ASCII",
			elem_type->u.basic.integer.base,
			elem_type->u.basic.integer.reverse_byte_order ? bo_reverse : bo_native,
			field->name, field->type.u.array.length);
		(*iter_field)++;
		break;
	}
	case ustctl_atype_sequence:
	{
		const struct ustctl_basic_type *elem_type;
		const struct ustctl_basic_type *length_type;

		elem_type = &field->type.u.sequence.elem_type;
		length_type = &field->type.u.sequence.length_type;
		ret = print_tabs(session, nesting);
		if (ret) {
			goto end;
		}
		ret = lttng_metadata_printf(session,
			"integer { size = %u; align = %u; signed = %u; encoding = %s; base = %u;%s } __%s_length;\n",
			length_type->u.basic.integer.size,
			(unsigned int) length_type->u.basic.integer.alignment,
			length_type->u.basic.integer.signedness,
			(length_type->u.basic.integer.encoding == ustctl_encode_none)
				? "none"
				: ((length_type->u.basic.integer.encoding == ustctl_encode_UTF8)
					? "UTF8"
					: "ASCII"),
			length_type->u.basic.integer.base,
			length_type->u.basic.integer.reverse_byte_order ? bo_reverse : bo_native,
			field->name);
		if (ret) {
			goto end;
		}

		ret = print_tabs(session, nesting);
		if (ret) {
			goto end;
		}
		ret = lttng_metadata_printf(session,
			"integer { size = %u; align = %u; signed = %u; encoding = %s; base = %u;%s } _%s[ __%s_length ];\n",
			elem_type->u.basic.integer.size,
			(unsigned int) elem_type->u.basic.integer.alignment,
			elem_type->u.basic.integer.signedness,
			(elem_type->u.basic.integer.encoding == ustctl_encode_none)
				? "none"
				: ((elem_type->u.basic.integer.encoding == ustctl_encode_UTF8)
					? "UTF8"
					: "ASCII"),
			elem_type->u.basic.integer.base,
			elem_type->u.basic.integer.reverse_byte_order ? bo_reverse : bo_native,
			field->name,
			field->name);
		(*iter_field)++;
		break;
	}

	case ustctl_atype_string:
		/* Default encoding is UTF8 */
		ret = print_tabs(session, nesting);
		if (ret) {
			goto end;
		}
		ret = lttng_metadata_printf(session,
			"string%s _%s;\n",
			field->type.u.basic.string.encoding == ustctl_encode_ASCII ?
				" { encoding = ASCII; }" : "",
			field->name);
		(*iter_field)++;
		break;
	case ustctl_atype_variant:
		ret = _lttng_variant_statedump(session, fields, nr_fields, iter_field, nesting);
		if (ret) {
			goto end;
		}
		break;
	case ustctl_atype_struct:
		ret = print_tabs(session, nesting);
		if (ret) {
			goto end;
		}
		ret = lttng_metadata_printf(session,
			"struct {} _%s;\n",
			field->name);
		(*iter_field)++;
		break;
	default:
		ret = -EINVAL;
	}
end:
	return ret;
}

static
int _lttng_context_metadata_statedump(struct ust_registry_session *session,
		size_t nr_ctx_fields,
		struct ustctl_field *ctx)
{
	int ret = 0;
	size_t i = 0;

	if (!ctx)
		return 0;
	for (;;) {
		if (i >= nr_ctx_fields) {
			break;
		}
		ret = _lttng_field_statedump(session, ctx,
				nr_ctx_fields, &i, 2);
		if (ret) {
			break;
		}
	}
	return ret;
}

static
int _lttng_fields_metadata_statedump(struct ust_registry_session *session,
		struct ust_registry_event *event)
{
	int ret = 0;
	size_t i = 0;

	for (;;) {
		if (i >= event->nr_fields) {
			break;
		}
		ret = _lttng_field_statedump(session, event->fields,
				event->nr_fields, &i, 2);
		if (ret) {
			break;
		}
	}
	return ret;
}

/*
 * Should be called with session registry mutex held.
 */
int ust_metadata_event_statedump(struct ust_registry_session *session,
		struct ust_registry_channel *chan,
		struct ust_registry_event *event)
{
	int ret = 0;

	/* Don't dump metadata events */
	if (chan->chan_id == -1U)
		return 0;

	ret = lttng_metadata_printf(session,
		"event {\n"
		"	name = \"%s\";\n"
		"	id = %u;\n"
		"	stream_id = %u;\n",
		event->name,
		event->id,
		chan->chan_id);
	if (ret)
		goto end;

	ret = lttng_metadata_printf(session,
		"	loglevel = %d;\n",
		event->loglevel_value);
	if (ret)
		goto end;

	if (event->model_emf_uri) {
		ret = lttng_metadata_printf(session,
			"	model.emf.uri = \"%s\";\n",
			event->model_emf_uri);
		if (ret)
			goto end;
	}

	ret = lttng_metadata_printf(session,
		"	fields := struct {\n"
		);
	if (ret)
		goto end;

	ret = _lttng_fields_metadata_statedump(session, event);
	if (ret)
		goto end;

	ret = lttng_metadata_printf(session,
		"	};\n"
		"};\n\n");
	if (ret)
		goto end;
	event->metadata_dumped = 1;

end:
	return ret;
}

/*
 * Should be called with session registry mutex held.
 */
int ust_metadata_channel_statedump(struct ust_registry_session *session,
		struct ust_registry_channel *chan)
{
	int ret = 0;

	/* Don't dump metadata events */
	if (chan->chan_id == -1U)
		return 0;

	if (!chan->header_type)
		return -EINVAL;

	ret = lttng_metadata_printf(session,
		"stream {\n"
		"	id = %u;\n"
		"	event.header := %s;\n"
		"	packet.context := struct packet_context;\n",
		chan->chan_id,
		chan->header_type == USTCTL_CHANNEL_HEADER_COMPACT ?
			"struct event_header_compact" :
			"struct event_header_large");
	if (ret)
		goto end;

	if (chan->ctx_fields) {
		ret = lttng_metadata_printf(session,
			"	event.context := struct {\n");
		if (ret)
			goto end;
	}
	ret = _lttng_context_metadata_statedump(session,
		chan->nr_ctx_fields,
		chan->ctx_fields);
	if (ret)
		goto end;
	if (chan->ctx_fields) {
		ret = lttng_metadata_printf(session,
			"	};\n");
		if (ret)
			goto end;
	}

	ret = lttng_metadata_printf(session,
		"};\n\n");
	/* Flag success of metadata dump. */
	chan->metadata_dumped = 1;

end:
	return ret;
}

static
int _lttng_stream_packet_context_declare(struct ust_registry_session *session)
{
	return lttng_metadata_printf(session,
		"struct packet_context {\n"
		"	uint64_clock_monotonic_t timestamp_begin;\n"
		"	uint64_clock_monotonic_t timestamp_end;\n"
		"	uint64_t content_size;\n"
		"	uint64_t packet_size;\n"
		"	uint64_t packet_seq_num;\n"
		"	unsigned long events_discarded;\n"
		"	uint32_t cpu_id;\n"
		"};\n\n"
		);
}

/*
 * Compact header:
 * id: range: 0 - 30.
 * id 31 is reserved to indicate an extended header.
 *
 * Large header:
 * id: range: 0 - 65534.
 * id 65535 is reserved to indicate an extended header.
 */
static
int _lttng_event_header_declare(struct ust_registry_session *session)
{
	return lttng_metadata_printf(session,
	"struct event_header_compact {\n"
	"	enum : uint5_t { compact = 0 ... 30, extended = 31 } id;\n"
	"	variant <id> {\n"
	"		struct {\n"
	"			uint27_clock_monotonic_t timestamp;\n"
	"		} compact;\n"
	"		struct {\n"
	"			uint32_t id;\n"
	"			uint64_clock_monotonic_t timestamp;\n"
	"		} extended;\n"
	"	} v;\n"
	"} align(%u);\n"
	"\n"
	"struct event_header_large {\n"
	"	enum : uint16_t { compact = 0 ... 65534, extended = 65535 } id;\n"
	"	variant <id> {\n"
	"		struct {\n"
	"			uint32_clock_monotonic_t timestamp;\n"
	"		} compact;\n"
	"		struct {\n"
	"			uint32_t id;\n"
	"			uint64_clock_monotonic_t timestamp;\n"
	"		} extended;\n"
	"	} v;\n"
	"} align(%u);\n\n",
	session->uint32_t_alignment,
	session->uint16_t_alignment
	);
}

/*
 * The offset between monotonic and realtime clock can be negative if
 * the system sets the REALTIME clock to 0 after boot.
 */
static
int measure_single_clock_offset(struct offset_sample *sample)
{
	uint64_t monotonic_avg, monotonic[2], measure_delta, realtime;
	uint64_t tcf = trace_clock_freq();
	struct timespec rts = { 0, 0 };
	int ret;

	monotonic[0] = trace_clock_read64();
	ret = lttng_clock_gettime(CLOCK_REALTIME, &rts);
	if (ret < 0) {
		return ret;
	}
	monotonic[1] = trace_clock_read64();
	measure_delta = monotonic[1] - monotonic[0];
	if (measure_delta > sample->measure_delta) {
		/*
		 * Discard value if it took longer to read than the best
		 * sample so far.
		 */
		return 0;
	}
	monotonic_avg = (monotonic[0] + monotonic[1]) >> 1;
	realtime = (uint64_t) rts.tv_sec * tcf;
	if (tcf == NSEC_PER_SEC) {
		realtime += rts.tv_nsec;
	} else {
		realtime += (uint64_t) rts.tv_nsec * tcf / NSEC_PER_SEC;
	}
	sample->offset = (int64_t) realtime - monotonic_avg;
	sample->measure_delta = measure_delta;
	return 0;
}

/*
 * Approximation of NTP time of day to clock monotonic correlation,
 * taken at start of trace. Keep the measurement that took the less time
 * to complete, thus removing imprecision caused by preemption.
 * May return a negative offset.
 */
static
int64_t measure_clock_offset(void)
{
	int i;
	struct offset_sample offset_best_sample = {
		.offset = 0,
		.measure_delta = UINT64_MAX,
	};

	for (i = 0; i < NR_CLOCK_OFFSET_SAMPLES; i++) {
		if (measure_single_clock_offset(&offset_best_sample)) {
			return 0;
		}
	}
	return offset_best_sample.offset;
}

/*
 * Should be called with session registry mutex held.
 */
int ust_metadata_session_statedump(struct ust_registry_session *session,
		struct ust_app *app,
		uint32_t major,
		uint32_t minor)
{
	unsigned char *uuid_c;
	char uuid_s[UUID_STR_LEN],
		clock_uuid_s[UUID_STR_LEN];
	int ret = 0;
	char hostname[HOST_NAME_MAX];

	assert(session);

	uuid_c = session->uuid;

	snprintf(uuid_s, sizeof(uuid_s),
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid_c[0], uuid_c[1], uuid_c[2], uuid_c[3],
		uuid_c[4], uuid_c[5], uuid_c[6], uuid_c[7],
		uuid_c[8], uuid_c[9], uuid_c[10], uuid_c[11],
		uuid_c[12], uuid_c[13], uuid_c[14], uuid_c[15]);

	/* For crash ABI */
	ret = lttng_metadata_printf(session,
		"/* CTF %u.%u */\n\n",
		CTF_SPEC_MAJOR,
		CTF_SPEC_MINOR);
	if (ret) {
		goto end;
	}

	ret = lttng_metadata_printf(session,
		"typealias integer { size = 8; align = %u; signed = false; } := uint8_t;\n"
		"typealias integer { size = 16; align = %u; signed = false; } := uint16_t;\n"
		"typealias integer { size = 32; align = %u; signed = false; } := uint32_t;\n"
		"typealias integer { size = 64; align = %u; signed = false; } := uint64_t;\n"
		"typealias integer { size = %u; align = %u; signed = false; } := unsigned long;\n"
		"typealias integer { size = 5; align = 1; signed = false; } := uint5_t;\n"
		"typealias integer { size = 27; align = 1; signed = false; } := uint27_t;\n"
		"\n"
		"trace {\n"
		"	major = %u;\n"
		"	minor = %u;\n"
		"	uuid = \"%s\";\n"
		"	byte_order = %s;\n"
		"	packet.header := struct {\n"
		"		uint32_t magic;\n"
		"		uint8_t  uuid[16];\n"
		"		uint32_t stream_id;\n"
		"		uint64_t stream_instance_id;\n"
		"	};\n"
		"};\n\n",
		session->uint8_t_alignment,
		session->uint16_t_alignment,
		session->uint32_t_alignment,
		session->uint64_t_alignment,
		session->bits_per_long,
		session->long_alignment,
		CTF_SPEC_MAJOR,
		CTF_SPEC_MINOR,
		uuid_s,
		session->byte_order == BIG_ENDIAN ? "be" : "le"
		);
	if (ret)
		goto end;

	/* ignore error, just use empty string if error. */
	hostname[0] = '\0';
	ret = gethostname(hostname, sizeof(hostname));
	if (ret && errno == ENAMETOOLONG)
		hostname[HOST_NAME_MAX - 1] = '\0';
	ret = lttng_metadata_printf(session,
		"env {\n"
		"	hostname = \"%s\";\n"
		"	domain = \"ust\";\n"
		"	tracer_name = \"lttng-ust\";\n"
		"	tracer_major = %u;\n"
		"	tracer_minor = %u;\n",
		hostname,
		major,
		minor
		);
	if (ret)
		goto end;

	/*
	 * If per-application registry, we can output extra information
	 * about the application.
	 */
	if (app) {
		ret = lttng_metadata_printf(session,
			"	tracer_patchlevel = %u;\n"
			"	vpid = %d;\n"
			"	procname = \"%s\";\n",
			app->version.patchlevel,
			(int) app->pid,
			app->name
			);
		if (ret)
			goto end;
	}

	ret = lttng_metadata_printf(session,
		"};\n\n"
		);
	if (ret)
		goto end;


	ret = lttng_metadata_printf(session,
		"clock {\n"
		"	name = \"%s\";\n",
		trace_clock_name()
		);
	if (ret)
		goto end;

	if (!trace_clock_uuid(clock_uuid_s)) {
		ret = lttng_metadata_printf(session,
			"	uuid = \"%s\";\n",
			clock_uuid_s
			);
		if (ret)
			goto end;
	}

	ret = lttng_metadata_printf(session,
		"	description = \"%s\";\n"
		"	freq = %" PRIu64 "; /* Frequency, in Hz */\n"
		"	/* clock value offset from Epoch is: offset * (1/freq) */\n"
		"	offset = %" PRId64 ";\n"
		"};\n\n",
		trace_clock_description(),
		trace_clock_freq(),
		measure_clock_offset()
		);
	if (ret)
		goto end;

	ret = lttng_metadata_printf(session,
		"typealias integer {\n"
		"	size = 27; align = 1; signed = false;\n"
		"	map = clock.%s.value;\n"
		"} := uint27_clock_monotonic_t;\n"
		"\n"
		"typealias integer {\n"
		"	size = 32; align = %u; signed = false;\n"
		"	map = clock.%s.value;\n"
		"} := uint32_clock_monotonic_t;\n"
		"\n"
		"typealias integer {\n"
		"	size = 64; align = %u; signed = false;\n"
		"	map = clock.%s.value;\n"
		"} := uint64_clock_monotonic_t;\n\n",
		trace_clock_name(),
		session->uint32_t_alignment,
		trace_clock_name(),
		session->uint64_t_alignment,
		trace_clock_name()
		);
	if (ret)
		goto end;

	ret = _lttng_stream_packet_context_declare(session);
	if (ret)
		goto end;

	ret = _lttng_event_header_declare(session);
	if (ret)
		goto end;

end:
	return ret;
}
