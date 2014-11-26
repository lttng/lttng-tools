%{
/*
 * filter-parser.y
 *
 * LTTng filter expression parser
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
 *
 * Grammar inspired from http://www.quut.com/c/ANSI-C-grammar-y.html
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

#include <common/macros.h>

#define WIDTH_u64_SCANF_IS_A_BROKEN_API	"20"
#define WIDTH_o64_SCANF_IS_A_BROKEN_API	"22"
#define WIDTH_x64_SCANF_IS_A_BROKEN_API	"17"
#define WIDTH_lg_SCANF_IS_A_BROKEN_API	"4096"	/* Hugely optimistic approximation */

LTTNG_HIDDEN
int yydebug;
LTTNG_HIDDEN
int filter_parser_debug = 0;

LTTNG_HIDDEN
int yyparse(struct filter_parser_ctx *parser_ctx, yyscan_t scanner);
LTTNG_HIDDEN
int yylex(union YYSTYPE *yyval, yyscan_t scanner);
LTTNG_HIDDEN
int yylex_init_extra(struct filter_parser_ctx *parser_ctx, yyscan_t * ptr_yy_globals);
LTTNG_HIDDEN
int yylex_destroy(yyscan_t yyparser_ctx);
LTTNG_HIDDEN
void yyrestart(FILE * in_str, yyscan_t parser_ctx);

struct gc_string {
	struct cds_list_head gc;
	size_t alloclen;
	char s[];
};

static const char *node_type_to_str[] = {
	[ NODE_UNKNOWN ] = "NODE_UNKNOWN",
	[ NODE_ROOT ] = "NODE_ROOT",
	[ NODE_EXPRESSION ] = "NODE_EXPRESSION",
	[ NODE_OP ] = "NODE_OP",
	[ NODE_UNARY_OP ] = "NODE_UNARY_OP",
};

LTTNG_HIDDEN
const char *node_type(struct filter_node *node)
{
	if (node->type < NR_NODE_TYPES)
		return node_type_to_str[node->type];
	else
		return NULL;
}

static struct gc_string *gc_string_alloc(struct filter_parser_ctx *parser_ctx,
					 size_t len)
{
	struct gc_string *gstr;
	size_t alloclen;

	/* TODO: could be faster with find first bit or glib Gstring */
	/* sizeof long to account for malloc header (int or long ?) */
	for (alloclen = 8; alloclen < sizeof(long) + sizeof(*gstr) + len;
	     alloclen *= 2);

	gstr = zmalloc(alloclen);
	if (!gstr) {
		goto end;
	}
	cds_list_add(&gstr->gc, &parser_ctx->allocated_strings);
	gstr->alloclen = alloclen;
end:
	return gstr;
}

/*
 * note: never use gc_string_append on a string that has external references.
 * gsrc will be garbage collected immediately, and gstr might be.
 * Should only be used to append characters to a string literal or constant.
 */
LTTNG_HIDDEN
struct gc_string *gc_string_append(struct filter_parser_ctx *parser_ctx,
				   struct gc_string *gstr,
				   struct gc_string *gsrc)
{
	size_t newlen = strlen(gsrc->s) + strlen(gstr->s) + 1;
	size_t alloclen;

	/* TODO: could be faster with find first bit or glib Gstring */
	/* sizeof long to account for malloc header (int or long ?) */
	for (alloclen = 8; alloclen < sizeof(long) + sizeof(*gstr) + newlen;
	     alloclen *= 2);

	if (alloclen > gstr->alloclen) {
		struct gc_string *newgstr;

		newgstr = gc_string_alloc(parser_ctx, newlen);
		strcpy(newgstr->s, gstr->s);
		strcat(newgstr->s, gsrc->s);
		cds_list_del(&gstr->gc);
		free(gstr);
		gstr = newgstr;
	} else {
		strcat(gstr->s, gsrc->s);
	}
	cds_list_del(&gsrc->gc);
	free(gsrc);
	return gstr;
}

LTTNG_HIDDEN
void setstring(struct filter_parser_ctx *parser_ctx, YYSTYPE *lvalp, const char *src)
{
	lvalp->gs = gc_string_alloc(parser_ctx, strlen(src) + 1);
	strcpy(lvalp->gs->s, src);
}

static struct filter_node *make_node(struct filter_parser_ctx *scanner,
				  enum node_type type)
{
	struct filter_ast *ast = filter_parser_get_ast(scanner);
	struct filter_node *node;

	node = zmalloc(sizeof(*node));
	if (!node)
		return NULL;
	memset(node, 0, sizeof(*node));
	node->type = type;
	cds_list_add(&node->gc, &ast->allocated_nodes);

	switch (type) {
	case NODE_ROOT:
		fprintf(stderr, "[error] %s: trying to create root node\n", __func__);
		break;

	case NODE_EXPRESSION:
		break;
	case NODE_OP:
		break;
	case NODE_UNARY_OP:
		break;

	case NODE_UNKNOWN:
	default:
		fprintf(stderr, "[error] %s: unknown node type %d\n", __func__,
			(int) type);
		break;
	}

	return node;
}

static struct filter_node *make_op_node(struct filter_parser_ctx *scanner,
			enum op_type type,
			struct filter_node *lchild,
			struct filter_node *rchild)
{
	struct filter_ast *ast = filter_parser_get_ast(scanner);
	struct filter_node *node;

	node = zmalloc(sizeof(*node));
	if (!node)
		return NULL;
	memset(node, 0, sizeof(*node));
	node->type = NODE_OP;
	cds_list_add(&node->gc, &ast->allocated_nodes);
	node->u.op.type = type;
	node->u.op.lchild = lchild;
	node->u.op.rchild = rchild;
	return node;
}

LTTNG_HIDDEN
void yyerror(struct filter_parser_ctx *parser_ctx, yyscan_t scanner, const char *str)
{
	fprintf(stderr, "error %s\n", str);
}
 
LTTNG_HIDDEN
int yywrap(void)
{
	return 1;
} 

#define parse_error(parser_ctx, str)				\
do {								\
	yyerror(parser_ctx, parser_ctx->scanner, YY_("parse error: " str "\n"));	\
	YYERROR;						\
} while (0)

static void free_strings(struct cds_list_head *list)
{
	struct gc_string *gstr, *tmp;

	cds_list_for_each_entry_safe(gstr, tmp, list, gc)
		free(gstr);
}

static struct filter_ast *filter_ast_alloc(void)
{
	struct filter_ast *ast;

	ast = zmalloc(sizeof(*ast));
	if (!ast)
		return NULL;
	memset(ast, 0, sizeof(*ast));
	CDS_INIT_LIST_HEAD(&ast->allocated_nodes);
	ast->root.type = NODE_ROOT;
	return ast;
}

static void filter_ast_free(struct filter_ast *ast)
{
	struct filter_node *node, *tmp;

	cds_list_for_each_entry_safe(node, tmp, &ast->allocated_nodes, gc)
		free(node);
	free(ast);
}

LTTNG_HIDDEN
int filter_parser_ctx_append_ast(struct filter_parser_ctx *parser_ctx)
{
	return yyparse(parser_ctx, parser_ctx->scanner);
}

LTTNG_HIDDEN
struct filter_parser_ctx *filter_parser_ctx_alloc(FILE *input)
{
	struct filter_parser_ctx *parser_ctx;
	int ret;

	yydebug = filter_parser_debug;

	parser_ctx = zmalloc(sizeof(*parser_ctx));
	if (!parser_ctx)
		return NULL;
	memset(parser_ctx, 0, sizeof(*parser_ctx));

	ret = yylex_init_extra(parser_ctx, &parser_ctx->scanner);
	if (ret) {
		fprintf(stderr, "yylex_init error\n");
		goto cleanup_parser_ctx;
	}
	/* Start processing new stream */
	yyrestart(input, parser_ctx->scanner);

	parser_ctx->ast = filter_ast_alloc();
	if (!parser_ctx->ast)
		goto cleanup_lexer;
	CDS_INIT_LIST_HEAD(&parser_ctx->allocated_strings);

	if (yydebug)
		fprintf(stdout, "parser_ctx input is a%s.\n",
			isatty(fileno(input)) ? "n interactive tty" :
						" noninteractive file");

	return parser_ctx;

cleanup_lexer:
	ret = yylex_destroy(parser_ctx->scanner);
	if (!ret)
		fprintf(stderr, "yylex_destroy error\n");
cleanup_parser_ctx:
	free(parser_ctx);
	return NULL;
}

LTTNG_HIDDEN
void filter_parser_ctx_free(struct filter_parser_ctx *parser_ctx)
{
	int ret;

	free_strings(&parser_ctx->allocated_strings);
	filter_ast_free(parser_ctx->ast);
	ret = yylex_destroy(parser_ctx->scanner);
	if (ret)
		fprintf(stderr, "yylex_destroy error\n");
	free(parser_ctx);
}

%}

%define api.pure
	/* %locations */
%parse-param {struct filter_parser_ctx *parser_ctx}
%parse-param {yyscan_t scanner}
%lex-param {yyscan_t scanner}
%start translation_unit
%token CHARACTER_CONSTANT_START SQUOTE STRING_LITERAL_START DQUOTE
%token ESCSEQ CHAR_STRING_TOKEN
%token DECIMAL_CONSTANT OCTAL_CONSTANT HEXADECIMAL_CONSTANT FLOAT_CONSTANT
%token LSBRAC RSBRAC LPAREN RPAREN LBRAC RBRAC RARROW
%token STAR PLUS MINUS
%token MOD_OP DIV_OP RIGHT_OP LEFT_OP
%token EQ_OP NE_OP LE_OP GE_OP LT_OP GT_OP AND_OP OR_OP NOT_OP
%token ASSIGN COLON SEMICOLON DOTDOTDOT DOT EQUAL COMMA
%token XOR_BIN AND_BIN OR_BIN NOT_BIN

%token <gs> IDENTIFIER GLOBAL_IDENTIFIER
%token ERROR
%union
{
	long long ll;
	char c;
	struct gc_string *gs;
	struct filter_node *n;
}

%type <gs> s_char s_char_sequence c_char c_char_sequence

%type <n> primary_expression
%type <n> postfix_expression
%type <n> unary_expression
%type <n> unary_operator
%type <n> multiplicative_expression
%type <n> additive_expression
%type <n> shift_expression
%type <n> relational_expression
%type <n> equality_expression
%type <n> and_expression
%type <n> exclusive_or_expression
%type <n> inclusive_or_expression
%type <n> logical_and_expression
%type <n> logical_or_expression
%type <n> expression

%%


/* 1.5 Constants */

c_char_sequence:
		c_char
		{	$$ = $1;					}
	|	c_char_sequence c_char
		{	$$ = gc_string_append(parser_ctx, $1, $2);		}
	;

c_char:
		CHAR_STRING_TOKEN
		{	$$ = yylval.gs;					}
	|	ESCSEQ
		{
			parse_error(parser_ctx, "escape sequences not supported yet");
		}
	;

/* 1.6 String literals */

s_char_sequence:
		s_char
		{	$$ = $1;					}
	|	s_char_sequence s_char
		{	$$ = gc_string_append(parser_ctx, $1, $2);		}
	;

s_char:
		CHAR_STRING_TOKEN
		{	$$ = yylval.gs;					}
	|	ESCSEQ
		{
			parse_error(parser_ctx, "escape sequences not supported yet");
		}
	;

primary_expression
	:	IDENTIFIER
		{
			$$ = make_node(parser_ctx, NODE_EXPRESSION);
			$$->u.expression.type = AST_EXP_IDENTIFIER;
			$$->u.expression.u.identifier = yylval.gs->s;
		}
	|	GLOBAL_IDENTIFIER
		{
			$$ = make_node(parser_ctx, NODE_EXPRESSION);
			$$->u.expression.type = AST_EXP_GLOBAL_IDENTIFIER;
			$$->u.expression.u.identifier = yylval.gs->s;
		}

	|	DECIMAL_CONSTANT
		{
			$$ = make_node(parser_ctx, NODE_EXPRESSION);
			$$->u.expression.type = AST_EXP_CONSTANT;
			if (sscanf(yylval.gs->s, "%" WIDTH_u64_SCANF_IS_A_BROKEN_API SCNu64,
					&$$->u.expression.u.constant) != 1) {
				parse_error(parser_ctx, "cannot scanf decimal constant");
			}
		}
	|	OCTAL_CONSTANT
		{
			$$ = make_node(parser_ctx, NODE_EXPRESSION);
			$$->u.expression.type = AST_EXP_CONSTANT;
			if (!strcmp(yylval.gs->s, "0")) {
				$$->u.expression.u.constant = 0;
			} else if (sscanf(yylval.gs->s, "0%" WIDTH_o64_SCANF_IS_A_BROKEN_API SCNo64,
					&$$->u.expression.u.constant) != 1) {
				parse_error(parser_ctx, "cannot scanf octal constant");
			}
		}
	|	HEXADECIMAL_CONSTANT
		{
			$$ = make_node(parser_ctx, NODE_EXPRESSION);
			$$->u.expression.type = AST_EXP_CONSTANT;
			if (sscanf(yylval.gs->s, "0x%" WIDTH_x64_SCANF_IS_A_BROKEN_API SCNx64,
					&$$->u.expression.u.constant) != 1) {
				parse_error(parser_ctx, "cannot scanf hexadecimal constant");
			}
		}
	|	FLOAT_CONSTANT
		{
			$$ = make_node(parser_ctx, NODE_EXPRESSION);
			$$->u.expression.type = AST_EXP_FLOAT_CONSTANT;
			if (sscanf(yylval.gs->s, "%" WIDTH_lg_SCANF_IS_A_BROKEN_API "lg",
					&$$->u.expression.u.float_constant) != 1) {
				parse_error(parser_ctx, "cannot scanf float constant");
			}
		}
	|	STRING_LITERAL_START DQUOTE
		{
			$$ = make_node(parser_ctx, NODE_EXPRESSION);
			$$->u.expression.type = AST_EXP_STRING;
			$$->u.expression.u.string = "";
		}
	|	STRING_LITERAL_START s_char_sequence DQUOTE
		{
			$$ = make_node(parser_ctx, NODE_EXPRESSION);
			$$->u.expression.type = AST_EXP_STRING;
			$$->u.expression.u.string = $2->s;
		}
	|	CHARACTER_CONSTANT_START c_char_sequence SQUOTE
		{
			$$ = make_node(parser_ctx, NODE_EXPRESSION);
			$$->u.expression.type = AST_EXP_STRING;
			$$->u.expression.u.string = $2->s;
		}
	|	LPAREN expression RPAREN
		{
			$$ = make_node(parser_ctx, NODE_EXPRESSION);
			$$->u.expression.type = AST_EXP_NESTED;
			$$->u.expression.u.child = $2;
		}
	;

postfix_expression
	: primary_expression
		{	$$ = $1;					}
	| postfix_expression DOT IDENTIFIER
		{
			$$ = make_node(parser_ctx, NODE_EXPRESSION);
			$$->u.expression.type = AST_EXP_IDENTIFIER;
			$$->u.expression.post_op = AST_LINK_DOT;
			$$->u.expression.u.identifier = $3->s;
			$$->u.expression.prev = $1;
		}
	| postfix_expression RARROW IDENTIFIER
		{
			$$ = make_node(parser_ctx, NODE_EXPRESSION);
			$$->u.expression.type = AST_EXP_IDENTIFIER;
			$$->u.expression.post_op = AST_LINK_RARROW;
			$$->u.expression.u.identifier = $3->s;
			$$->u.expression.prev = $1;
		}
	;

unary_expression
	: postfix_expression
		{	$$ = $1;					}
	| unary_operator unary_expression
		{
			$$ = $1;
			$$->u.unary_op.child = $2;
		}
	;

unary_operator
	: PLUS
		{
			$$ = make_node(parser_ctx, NODE_UNARY_OP);
			$$->u.unary_op.type = AST_UNARY_PLUS;
		}
	| MINUS
		{
			$$ = make_node(parser_ctx, NODE_UNARY_OP);
			$$->u.unary_op.type = AST_UNARY_MINUS;
		}
	| NOT_OP
		{
			$$ = make_node(parser_ctx, NODE_UNARY_OP);
			$$->u.unary_op.type = AST_UNARY_NOT;
		}
	| NOT_BIN
		{
			$$ = make_node(parser_ctx, NODE_UNARY_OP);
			$$->u.unary_op.type = AST_UNARY_BIN_NOT;
		}
	;

multiplicative_expression
	: unary_expression
		{	$$ = $1;					}
	| multiplicative_expression STAR unary_expression
		{
			$$ = make_op_node(parser_ctx, AST_OP_MUL, $1, $3);
		}
	| multiplicative_expression DIV_OP unary_expression
		{
			$$ = make_op_node(parser_ctx, AST_OP_DIV, $1, $3);
		}
	| multiplicative_expression MOD_OP unary_expression
		{
			$$ = make_op_node(parser_ctx, AST_OP_MOD, $1, $3);
		}
	;

additive_expression
	: multiplicative_expression
		{	$$ = $1;					}
	| additive_expression PLUS multiplicative_expression
		{
			$$ = make_op_node(parser_ctx, AST_OP_PLUS, $1, $3);
		}
	| additive_expression MINUS multiplicative_expression
		{
			$$ = make_op_node(parser_ctx, AST_OP_MINUS, $1, $3);
		}
	;

shift_expression
	: additive_expression
		{	$$ = $1;					}
	| shift_expression LEFT_OP additive_expression
		{
			$$ = make_op_node(parser_ctx, AST_OP_LSHIFT, $1, $3);
		}
	| shift_expression RIGHT_OP additive_expression
		{
			$$ = make_op_node(parser_ctx, AST_OP_RSHIFT, $1, $3);
		}
	;

relational_expression
	: shift_expression
		{	$$ = $1;					}
	| relational_expression LT_OP shift_expression
		{
			$$ = make_op_node(parser_ctx, AST_OP_LT, $1, $3);
		}
	| relational_expression GT_OP shift_expression
		{
			$$ = make_op_node(parser_ctx, AST_OP_GT, $1, $3);
		}
	| relational_expression LE_OP shift_expression
		{
			$$ = make_op_node(parser_ctx, AST_OP_LE, $1, $3);
		}
	| relational_expression GE_OP shift_expression
		{
			$$ = make_op_node(parser_ctx, AST_OP_GE, $1, $3);
		}
	;

equality_expression
	: relational_expression
		{	$$ = $1;					}
	| equality_expression EQ_OP relational_expression
		{
			$$ = make_op_node(parser_ctx, AST_OP_EQ, $1, $3);
		}
	| equality_expression NE_OP relational_expression
		{
			$$ = make_op_node(parser_ctx, AST_OP_NE, $1, $3);
		}
	;

and_expression
	: equality_expression
		{	$$ = $1;					}
	| and_expression AND_BIN equality_expression
		{
			$$ = make_op_node(parser_ctx, AST_OP_BIN_AND, $1, $3);
		}
	;

exclusive_or_expression
	: and_expression
		{	$$ = $1;					}
	| exclusive_or_expression XOR_BIN and_expression
		{
			$$ = make_op_node(parser_ctx, AST_OP_BIN_XOR, $1, $3);
		}
	;

inclusive_or_expression
	: exclusive_or_expression
		{	$$ = $1;					}
	| inclusive_or_expression OR_BIN exclusive_or_expression
		{
			$$ = make_op_node(parser_ctx, AST_OP_BIN_OR, $1, $3);
		}
	;

logical_and_expression
	: inclusive_or_expression
		{	$$ = $1;					}
	| logical_and_expression AND_OP inclusive_or_expression
		{
			$$ = make_op_node(parser_ctx, AST_OP_AND, $1, $3);
		}
	;

logical_or_expression
	: logical_and_expression
		{	$$ = $1;					}
	| logical_or_expression OR_OP logical_and_expression
		{
			$$ = make_op_node(parser_ctx, AST_OP_OR, $1, $3);
		}
	;

expression
	: logical_or_expression
		{	$$ = $1;					}
	;

translation_unit
	: expression
		{
			parser_ctx->ast->root.u.root.child = $1;
		}
	;
