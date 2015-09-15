/*
 * filter-grammar-test.c
 *
 * LTTng filter grammar test
 *
 * Copyright 2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include "filter-ast.h"
#include "filter-parser.h"
#include "filter-bytecode.h"

int main(int argc, char **argv)
{
	struct filter_parser_ctx *ctx;
	int ret;
	int print_xml = 0, generate_ir = 0, generate_bytecode = 0,
		print_bytecode = 0;
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-p") == 0)
			print_xml = 1;
		else if (strcmp(argv[i], "-i") == 0)
			generate_ir = 1;
		else if (strcmp(argv[i], "-b") == 0)
			generate_bytecode = 1;
		else if (strcmp(argv[i], "-d") == 0)
			filter_parser_debug = 1;
		else if (strcmp(argv[i], "-B") == 0)
			print_bytecode = 1;
	}

	ctx = filter_parser_ctx_alloc(stdin);
	if (!ctx) {
		fprintf(stderr, "Error allocating parser\n");
		goto alloc_error;
	}
	ret = filter_parser_ctx_append_ast(ctx);
	if (ret) {
		fprintf(stderr, "Parse error\n");
		goto parse_error;
	}
	ret = filter_visitor_set_parent(ctx);
	if (ret) {
		fprintf(stderr, "Set parent error\n");
		goto parse_error;
	}
	if (print_xml) {
		ret = filter_visitor_print_xml(ctx, stdout, 0);
		if (ret) {
			fflush(stdout);
			fprintf(stderr, "XML print error\n");
			goto parse_error;
		}
	}
	if (generate_ir) {
		printf("Generating IR... ");
		fflush(stdout);
		ret = filter_visitor_ir_generate(ctx);
		if (ret) {
			fprintf(stderr, "Generate IR error\n");
			goto parse_error;
		}
		printf("done\n");

		printf("Validating IR... ");
		fflush(stdout);
		ret = filter_visitor_ir_check_binary_op_nesting(ctx);
		if (ret) {
			goto parse_error;
		}
		printf("done\n");
	}
	if (generate_bytecode) {
		printf("Generating bytecode... ");
		fflush(stdout);
		ret = filter_visitor_bytecode_generate(ctx);
		if (ret) {
			fprintf(stderr, "Generate bytecode error\n");
			goto parse_error;
		}
		printf("done\n");
		printf("Size of bytecode generated: %u bytes.\n",
			bytecode_get_len(&ctx->bytecode->b));
	}

	if (print_bytecode) {
		unsigned int bytecode_len, len, i;

		len = bytecode_get_len(&ctx->bytecode->b);
		bytecode_len = ctx->bytecode->b.reloc_table_offset;
		printf("Bytecode:\n");
		for (i = 0; i < bytecode_len; i++) {
			printf("0x%X ",
				((uint8_t *) ctx->bytecode->b.data)[i]);
		}
		printf("\n");
		printf("Reloc table:\n");
		for (i = bytecode_len; i < len;) {
			printf("{ 0x%X, ",
				*(uint16_t *) &ctx->bytecode->b.data[i]);
			i += sizeof(uint16_t);
			printf("%s } ", &((char *) ctx->bytecode->b.data)[i]);
			i += strlen(&((char *) ctx->bytecode->b.data)[i]) + 1;
		}
		printf("\n");
	}

	filter_bytecode_free(ctx);
	filter_ir_free(ctx);
	filter_parser_ctx_free(ctx);
	return 0;

parse_error:
	filter_bytecode_free(ctx);
	filter_ir_free(ctx);
	filter_parser_ctx_free(ctx);
alloc_error:
	exit(EXIT_FAILURE);
}
