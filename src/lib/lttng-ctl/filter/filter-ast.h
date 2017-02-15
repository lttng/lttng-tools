#ifndef _FILTER_AST_H
#define _FILTER_AST_H

/*
 * filter-ast.h
 *
 * LTTng filter AST
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

/*
 * Note: filter-ast.h should be included before filter-parser.h.
 */

#include <urcu/list.h>
#include <stdint.h>

#define printf_debug(fmt, args...)					\
	do {								\
		if (filter_parser_debug)				\
			fprintf(stdout, "[debug] " fmt, ## args);	\
	} while (0)

// the parameter name (of the reentrant 'yyparse' function)
// data is a pointer to a 'SParserParam' structure
//#define YYPARSE_PARAM	parser_ctx

#ifndef YY_TYPEDEF_YY_SCANNER_T
#define YY_TYPEDEF_YY_SCANNER_T
typedef void* yyscan_t;
#endif

extern int filter_parser_debug;

struct filter_node;
struct filter_parser;

enum node_type {
	NODE_UNKNOWN = 0,
	NODE_ROOT,

	NODE_EXPRESSION,
	NODE_OP,
	NODE_UNARY_OP,

	NR_NODE_TYPES,
};

enum op_type {
	AST_OP_UNKNOWN = 0,
	AST_OP_MUL,
	AST_OP_DIV,
	AST_OP_MOD,
	AST_OP_PLUS,
	AST_OP_MINUS,
	AST_OP_RSHIFT,
	AST_OP_LSHIFT,
	AST_OP_AND,
	AST_OP_OR,
	AST_OP_BIN_AND,
	AST_OP_BIN_OR,
	AST_OP_BIN_XOR,

	AST_OP_EQ,
	AST_OP_NE,
	AST_OP_GT,
	AST_OP_LT,
	AST_OP_GE,
	AST_OP_LE,
};

enum unary_op_type {
	AST_UNARY_UNKNOWN = 0,
	AST_UNARY_PLUS,
	AST_UNARY_MINUS,
	AST_UNARY_NOT,
	AST_UNARY_BIN_NOT,
};

enum ast_link_type {
	AST_LINK_UNKNOWN = 0,
	AST_LINK_DOT,
	AST_LINK_RARROW,
};

struct filter_node {
	/*
	 * Parent node is only set on demand by specific visitor.
	 */
	struct filter_node *parent;
	struct cds_list_head gc;

	enum node_type type;
	union {
		struct {
		} unknown;
		struct {
			struct filter_node *child;
		} root;
		struct {
			enum {
				AST_EXP_UNKNOWN = 0,
				AST_EXP_STRING,
				AST_EXP_CONSTANT,
				AST_EXP_FLOAT_CONSTANT,
				AST_EXP_IDENTIFIER,
				AST_EXP_GLOBAL_IDENTIFIER,
				AST_EXP_NESTED,
			} type;
			enum ast_link_type post_op;	/* reverse */
			enum ast_link_type pre_op;	/* forward */
			union {
				char *string;
				uint64_t constant;
				double float_constant;
				char *identifier;
				/*
				 * child can be nested.
				 */
				struct filter_node *child;
			} u;
			/* linked dot/arrow chain */
			struct filter_node *prev;
			struct filter_node *next;
		} expression;
		struct {
			enum op_type type;
			struct filter_node *lchild;
			struct filter_node *rchild;
		} op;
		struct {
			enum unary_op_type type;
			struct filter_node *child;
		} unary_op;
	} u;
};

struct filter_ast {
	struct filter_node root;
	struct cds_list_head allocated_nodes;
};

const char *node_type(struct filter_node *node);

struct ir_op;

struct filter_parser_ctx {
	yyscan_t scanner;
	struct filter_ast *ast;
	struct cds_list_head allocated_strings;
	struct ir_op *ir_root;
	struct lttng_filter_bytecode_alloc *bytecode;
	struct lttng_filter_bytecode_alloc *bytecode_reloc;
};

struct filter_parser_ctx *filter_parser_ctx_alloc(FILE *input);
void filter_parser_ctx_free(struct filter_parser_ctx *parser_ctx);
int filter_parser_ctx_append_ast(struct filter_parser_ctx *parser_ctx);

static inline
struct filter_ast *filter_parser_get_ast(struct filter_parser_ctx *parser_ctx)
{
	return parser_ctx->ast;
}

int filter_visitor_set_parent(struct filter_parser_ctx *ctx);
int filter_visitor_print_xml(struct filter_parser_ctx *ctx, FILE *stream,
			int indent);
int filter_visitor_ir_generate(struct filter_parser_ctx *ctx);
void filter_ir_free(struct filter_parser_ctx *ctx);
int filter_visitor_bytecode_generate(struct filter_parser_ctx *ctx);
void filter_bytecode_free(struct filter_parser_ctx *ctx);
int filter_visitor_ir_check_binary_op_nesting(struct filter_parser_ctx *ctx);
int filter_visitor_ir_check_binary_comparator(struct filter_parser_ctx *ctx);
int filter_visitor_ir_validate_string(struct filter_parser_ctx *ctx);
int filter_visitor_ir_normalize_glob_patterns(struct filter_parser_ctx *ctx);
int filter_visitor_ir_validate_globbing(struct filter_parser_ctx *ctx);

#endif /* _FILTER_AST_H */
