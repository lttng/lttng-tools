/*
 * Copyright 2020 EfficiOS, Inc.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "event-expr-to-bytecode.h"

#include <stdio.h>
#include <lttng/event-expr.h>
#include <common/bytecode/bytecode.h>
#include <common/error.h>

static
int event_expr_to_bytecode_recursive(const struct lttng_event_expr *expr,
		struct lttng_bytecode_alloc **bytecode,
		struct lttng_bytecode_alloc **bytecode_reloc)
{
	int status;
	enum lttng_event_expr_status event_expr_status;

	switch (lttng_event_expr_get_type(expr)) {
	case LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD:
	{
		const char *name;

		status = bytecode_push_get_payload_root(bytecode);
		if (status) {
			ERR("Failed to get payload root from bytecode");
			goto end;
		}

		name = lttng_event_expr_event_payload_field_get_name(expr);
		if (!name) {
			ERR("Failed to get payload field name from event expression");
			status = -1;
			goto end;
		}

		status = bytecode_push_get_symbol(bytecode, bytecode_reloc, name);
		if (status) {
			ERR("Failed to push 'get symbol %s' in bytecode", name);
			goto end;
		}

		break;
	}
	case LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD:
	{
		const char *name;

		status = bytecode_push_get_context_root(bytecode);
		if (status) {
			ERR("Failed to get context root from bytecode");
			goto end;
		}

		name = lttng_event_expr_channel_context_field_get_name(expr);
		if (!name) {
			ERR("Failed to get channel context field name from event expression");
			status = -1;
			goto end;
		}

		status = bytecode_push_get_symbol(bytecode, bytecode_reloc, name);
		if (status) {
			ERR("Failed to push 'get symbol %s' in bytecode", name);
			goto end;
		}

		break;
	}
	case LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD:
	{
		int ret;
		char *name = NULL;
		const char *provider_name, *type_name;

		status = bytecode_push_get_app_context_root(bytecode);
		if (status) {
			ERR("Failed to get application context root from bytecode");
			goto end;
		}

		provider_name = lttng_event_expr_app_specific_context_field_get_provider_name(
				expr);
		if (!provider_name) {
			ERR("Failed to get application context provider name from event expression");
			status = -1;
			goto end;
		}

		type_name = lttng_event_expr_app_specific_context_field_get_type_name(
				expr);
		if (!type_name) {
			ERR("Failed to get application context type name from event expression");
			status = -1;
			goto end;
		}

		/*
		 * Reconstitute the app context field name from its two parts.
		 */
		ret = asprintf(&name, "%s:%s", provider_name, type_name);
		if (ret < 0) {
			PERROR("Failed to format application specific context: provider_name = '%s', type_name = '%s'",
					provider_name, type_name);
			status = -1;
			goto end;
		}

		status = bytecode_push_get_symbol(
				bytecode, bytecode_reloc, name);
		free(name);
		if (status) {
			ERR("Failed to push 'get symbol %s' in bytecode", name);
			goto end;
		}

		break;
	}
	case LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT:
	{
		unsigned int index;
		const struct lttng_event_expr *parent;

		parent = lttng_event_expr_array_field_element_get_parent_expr(
				expr);
		if (!parent) {
			ERR("Failed to get parent expression from array event expression");
			status = -1;
			goto end;
		}

		status = event_expr_to_bytecode_recursive(
				parent, bytecode, bytecode_reloc);
		if (status) {
			goto end;
		}

		event_expr_status = lttng_event_expr_array_field_element_get_index(
				expr, &index);
		if (event_expr_status != LTTNG_EVENT_EXPR_STATUS_OK) {
			ERR("Failed to get array field element index from event expression");
			status = -1;
			goto end;
		}

		status = bytecode_push_get_index_u64(bytecode, index);
		if (status) {
			ERR("Failed to push 'get index %u' in bytecode", index);
			goto end;
		}

		break;
	}
	default:
		abort();
	}

	status = 0;
end:
	return status;
}

LTTNG_HIDDEN
int lttng_event_expr_to_bytecode(const struct lttng_event_expr *expr,
		struct lttng_bytecode **bytecode_out)
{
	int status;
	struct return_op ret_insn;
	struct lttng_bytecode_alloc *bytecode = NULL;
	struct lttng_bytecode_alloc *bytecode_reloc = NULL;

	status = bytecode_init(&bytecode);
	if (status) {
		ERR("Failed to initialize bytecode");
		goto end;
	}

	status = bytecode_init(&bytecode_reloc);
	if (status) {
		ERR("Failed to initialize relocation bytecode");
		goto end;
	}

	status = event_expr_to_bytecode_recursive(
			expr, &bytecode, &bytecode_reloc);
	if (status) {
		/* Errors already logged. */
		goto end;
	}

	ret_insn.op = BYTECODE_OP_RETURN;
	bytecode_push(&bytecode, &ret_insn, 1, sizeof(ret_insn));

	/* Append symbol table to bytecode. */
	bytecode->b.reloc_table_offset = bytecode_get_len(&bytecode->b);
	status = bytecode_push(&bytecode, bytecode_reloc->b.data, 1,
			bytecode_get_len(&bytecode_reloc->b));
	if (status) {
		ERR("Failed to push symbol table to bytecode");
		goto end;
	}

	/* Copy the `lttng_bytecode` out of the `lttng_bytecode_alloc`.  */
	*bytecode_out = lttng_bytecode_copy(&bytecode->b);
	if (!*bytecode_out) {
		status = -1;
		goto end;
	}

end:
	if (bytecode) {
		free(bytecode);
	}

	if (bytecode_reloc) {
		free(bytecode_reloc);
	}

	return status;
}
