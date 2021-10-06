%{
/*
 * filter-lexer.l
 *
 * LTTng filter lexer
 *
 * Copyright 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <stdio.h>
#include "filter-ast.h"
#include "filter-parser.h"
#include <lttng/lttng-export.h>

static void yyunput (int c, register char * yy_bp , yyscan_t yyscanner)
	__attribute__((unused));
static int input (yyscan_t yyscanner) __attribute__((unused));

%}

%x comment_ml comment_sl string_lit char_const
%option reentrant yylineno noyywrap bison-bridge
%option extra-type="struct filter_parser_ctx *"
	/* bison-locations */

D				[0-9]
L				[a-zA-Z_]
H				[a-fA-F0-9]
E				([Ee][+-]?{D}+)
P				([Pp][+-]?{D}+)
FS				(f|F|l|L)
IS				((u|U)|(u|U)?(l|L|ll|LL)|(l|L|ll|LL)(u|U))

INTEGER_SUFFIX			[ \n\t]*(U|UL|ULL|LU|LLU|Ul|Ull|lU|llU|u|uL|uLL|Lu|LLu|ul|ull|lu|llu)
DIGIT				[0-9]
NONDIGIT			[a-zA-Z_]
HEXDIGIT			[0-9A-Fa-f]
OCTALDIGIT			[0-7]
UCHARLOWERCASE			\\u{HEXDIGIT}{4}
UCHARUPPERCASE			\\U{HEXDIGIT}{8}
ID_EXTRA_CHAR			(":")
ID_NONDIGIT			{NONDIGIT}|{UCHARLOWERCASE}|{UCHARUPPERCASE}|{ID_EXTRA_CHAR}
IDENTIFIER			{ID_NONDIGIT}({ID_NONDIGIT}|{DIGIT})*
ESCSEQ				\\(\'|\"|\?|\\|a|b|f|n|r|t|v|{OCTALDIGIT}{1,3}|u{HEXDIGIT}{4}|U{HEXDIGIT}{8}|x{HEXDIGIT}+)
%%

				/*
				 * Using start conditions to deal with comments
				 * and strings.
				 */ 

"/*"				BEGIN(comment_ml);
<comment_ml>[^*\n]*		/* eat anything that's not a '*' */
<comment_ml>"*"+[^*/\n]*	/* eat up '*'s not followed by '/'s */
<comment_ml>\n			++yylineno;
<comment_ml>"*"+"/"		BEGIN(INITIAL);

"//"				BEGIN(comment_sl);
<comment_sl>[^\n]*\n		++yylineno; BEGIN(INITIAL);

L\'				BEGIN(char_const); return CHARACTER_CONSTANT_START;
\'				BEGIN(char_const); return CHARACTER_CONSTANT_START;
<char_const>\'			BEGIN(INITIAL); return SQUOTE;

L\"				BEGIN(string_lit); return STRING_LITERAL_START;
\"				BEGIN(string_lit); return STRING_LITERAL_START;
<string_lit>\"			BEGIN(INITIAL); return DQUOTE;

<char_const,string_lit>ESCSEQ	return ESCSEQ;
<char_const,string_lit>\n	; /* ignore */
<char_const,string_lit>.	setstring(yyextra, yylval, yytext); return CHAR_STRING_TOKEN;


0[xX]{H}+{IS}?			setstring(yyextra, yylval, yytext); return HEXADECIMAL_CONSTANT;
0[0-7]*{IS}?			setstring(yyextra, yylval, yytext); return OCTAL_CONSTANT;
[1-9]{D}*{IS}?			setstring(yyextra, yylval, yytext); return DECIMAL_CONSTANT;

{D}+{E}{FS}?			setstring(yyextra, yylval, yytext); return FLOAT_CONSTANT;
{D}*"."{D}+{E}?{FS}?		setstring(yyextra, yylval, yytext); return FLOAT_CONSTANT;
{D}+"."{D}*{E}?{FS}?		setstring(yyextra, yylval, yytext); return FLOAT_CONSTANT;
0[xX]{H}+{P}{FS}?		setstring(yyextra, yylval, yytext); return FLOAT_CONSTANT;
0[xX]{H}*"."{H}+{P}?{FS}?  	setstring(yyextra, yylval, yytext); return FLOAT_CONSTANT;
0[xX]{H}+"."{H}*{P}?{FS}?     	setstring(yyextra, yylval, yytext); return FLOAT_CONSTANT;

"["				return LSBRAC;
"]"				return RSBRAC;
"("				return LPAREN;
")"				return RPAREN;
"{"				return LBRAC;
"}"				return RBRAC;
"->"				return RARROW;

"*"				return STAR;
"+"				return PLUS;
"-"				return MINUS;

"%"				return MOD_OP;
"/"				return DIV_OP;
">>"				return RIGHT_OP;
"<<"				return LEFT_OP;

"=="				return EQ_OP;
"!="				return NE_OP;
"<="				return LE_OP;
">="				return GE_OP;
"<"				return LT_OP;
">"				return GT_OP;
"&&"				return AND_OP;
"||"				return OR_OP;
"!"				return NOT_OP;

":="				return ASSIGN;
":"				return COLON;
";"				return SEMICOLON;
"..."				return DOTDOTDOT;
"."				return DOT;
"="				return EQUAL;
","				return COMMA;
"^"				return XOR_BIN;
"&"				return AND_BIN;
"|"				return OR_BIN;
"~"				return NOT_BIN;
"$"{IDENTIFIER}			printf_debug("<GLOBAL_IDENTIFIER %s>\n", yytext); setstring(yyextra, yylval, yytext); return GLOBAL_IDENTIFIER;
{IDENTIFIER}			printf_debug("<IDENTIFIER %s>\n", yytext); setstring(yyextra, yylval, yytext); return IDENTIFIER;
[ \t\n]+			; /* ignore */
.				return ERROR;
%%

/*
 * The lexer symbols were (e.g. lttng_yy_create_buffer) were mistakenly
 * exported in the past, so must stay exported.  Since it is difficult to tweak
 * how the lexer functions are emitted, the strategy used here was to use a
 * different prefix for the symbols (`lttng_filter_`) and define aliases with
 * the old prefix (`lttng_`).
 *
 * The `MAKE_ALIAS` macro defines one such alias.
 */
LTTNG_EXPORT
YY_BUFFER_STATE lttng_yy_create_buffer(FILE *file, int size, yyscan_t yyscanner);
YY_BUFFER_STATE lttng_yy_create_buffer(FILE *file, int size, yyscan_t yyscanner)
{
	return yy_create_buffer(file, size, yyscanner);
}

LTTNG_EXPORT
void lttng_yy_delete_buffer(YY_BUFFER_STATE b, yyscan_t yyscanner);
void lttng_yy_delete_buffer(YY_BUFFER_STATE b, yyscan_t yyscanner)
{
	return yy_delete_buffer(b, yyscanner);
}

LTTNG_EXPORT
void lttng_yy_flush_buffer (YY_BUFFER_STATE b, yyscan_t yyscanner);
void lttng_yy_flush_buffer (YY_BUFFER_STATE b, yyscan_t yyscanner)
{
	return yy_flush_buffer(b, yyscanner);
}

LTTNG_EXPORT
YY_BUFFER_STATE lttng_yy_scan_buffer(char *base, yy_size_t size, yyscan_t yyscanner);
YY_BUFFER_STATE lttng_yy_scan_buffer(char *base, yy_size_t size, yyscan_t yyscanner)
{
	return yy_scan_buffer(base, size, yyscanner);
}

LTTNG_EXPORT
YY_BUFFER_STATE lttng_yy_scan_bytes(const char *bytes, int len, yyscan_t yyscanner);
YY_BUFFER_STATE lttng_yy_scan_bytes(const char *bytes, int len, yyscan_t yyscanner)
{
	return yy_scan_bytes(bytes, len, yyscanner);
}

LTTNG_EXPORT
YY_BUFFER_STATE lttng_yy_scan_string(const char *yy_str, yyscan_t yyscanner);
YY_BUFFER_STATE lttng_yy_scan_string(const char *yy_str, yyscan_t yyscanner)
{
	return yy_scan_string(yy_str, yyscanner);
}

LTTNG_EXPORT
void lttng_yy_switch_to_buffer(YY_BUFFER_STATE new_buffer, yyscan_t yyscanner);
void lttng_yy_switch_to_buffer(YY_BUFFER_STATE new_buffer, yyscan_t yyscanner)
{
	return yy_switch_to_buffer(new_buffer, yyscanner);
}

LTTNG_EXPORT
void *lttng_yyalloc(yy_size_t s, yyscan_t yyscanner);
void *lttng_yyalloc(yy_size_t s, yyscan_t yyscanner)
{
	return yyalloc(s, yyscanner);
}

LTTNG_EXPORT
void lttng_yyfree(void *p, yyscan_t yyscanner);
void lttng_yyfree(void *p, yyscan_t yyscanner)
{
	return yyfree(p, yyscanner);
}

LTTNG_EXPORT
int lttng_yyget_column(yyscan_t yyscanner);
int lttng_yyget_column(yyscan_t yyscanner)
{
	return yyget_column(yyscanner);
}

LTTNG_EXPORT
int lttng_yyget_debug(yyscan_t yyscanner);
int lttng_yyget_debug(yyscan_t yyscanner)
{
	return yyget_debug(yyscanner);
}

LTTNG_EXPORT
YY_EXTRA_TYPE lttng_yyget_extra(yyscan_t yyscanner);
YY_EXTRA_TYPE lttng_yyget_extra(yyscan_t yyscanner)
{
	return yyget_extra(yyscanner);
}

LTTNG_EXPORT
FILE *lttng_yyget_in(yyscan_t yyscanner);
FILE *lttng_yyget_in(yyscan_t yyscanner)
{
	return yyget_in(yyscanner);
}

LTTNG_EXPORT
int lttng_yyget_leng(yyscan_t yyscanner);
int lttng_yyget_leng(yyscan_t yyscanner)
{
	return yyget_leng(yyscanner);
}

LTTNG_EXPORT
int lttng_yyget_lineno(yyscan_t yyscanner);
int lttng_yyget_lineno(yyscan_t yyscanner)
{
	return yyget_lineno(yyscanner);
}

LTTNG_EXPORT
YYSTYPE *lttng_yyget_lval(yyscan_t yyscanner);
YYSTYPE *lttng_yyget_lval(yyscan_t yyscanner)
{
	return yyget_lval(yyscanner);
}

LTTNG_EXPORT
FILE *lttng_yyget_out(yyscan_t yyscanner);
FILE *lttng_yyget_out(yyscan_t yyscanner)
{
	return yyget_out(yyscanner);
}

LTTNG_EXPORT
char *lttng_yyget_text(yyscan_t yyscanner);
char *lttng_yyget_text(yyscan_t yyscanner)
{
	return yyget_text(yyscanner);
}

LTTNG_EXPORT
int lttng_yylex_init(yyscan_t *scanner);
int lttng_yylex_init(yyscan_t *scanner)
{
	return yylex_init(scanner);
}

LTTNG_EXPORT
void lttng_yypop_buffer_state(yyscan_t yyscanner);
void lttng_yypop_buffer_state(yyscan_t yyscanner)
{
	return yypop_buffer_state(yyscanner);
}

LTTNG_EXPORT
void lttng_yypush_buffer_state(YY_BUFFER_STATE new_buffer, yyscan_t yyscanner);
void lttng_yypush_buffer_state(YY_BUFFER_STATE new_buffer, yyscan_t yyscanner)
{
	return yypush_buffer_state(new_buffer, yyscanner);
}

LTTNG_EXPORT
void *lttng_yyrealloc(void *p, yy_size_t s, yyscan_t yyscanner);
void *lttng_yyrealloc(void *p, yy_size_t s, yyscan_t yyscanner)
{
	return yyrealloc(p, s, yyscanner);
}

LTTNG_EXPORT
void lttng_yyset_column(int _column_no, yyscan_t yyscanner);
void lttng_yyset_column(int _column_no, yyscan_t yyscanner)
{
	return yyset_column(_column_no, yyscanner);
}

LTTNG_EXPORT
void lttng_yyset_debug(int debug_flag, yyscan_t yyscanner);
void lttng_yyset_debug(int debug_flag, yyscan_t yyscanner)
{
	return yyset_debug(debug_flag, yyscanner);
}

LTTNG_EXPORT
void lttng_yyset_extra(YY_EXTRA_TYPE user_defined, yyscan_t yyscanner);
void lttng_yyset_extra(YY_EXTRA_TYPE user_defined, yyscan_t yyscanner)
{
	return yyset_extra(user_defined, yyscanner);
}

LTTNG_EXPORT
void lttng_yyset_in(FILE *_in_str, yyscan_t yyscanner);
void lttng_yyset_in(FILE *_in_str, yyscan_t yyscanner)
{
	return yyset_in(_in_str, yyscanner);
}

LTTNG_EXPORT
void lttng_yyset_lineno(int _line_number, yyscan_t yyscanner);
void lttng_yyset_lineno(int _line_number, yyscan_t yyscanner)
{
	return yyset_lineno(_line_number, yyscanner);
}

LTTNG_EXPORT
void lttng_yyset_lval(YYSTYPE *yylval_param, yyscan_t yyscanner);
void lttng_yyset_lval(YYSTYPE *yylval_param, yyscan_t yyscanner)
{
	return yyset_lval(yylval_param, yyscanner);
}

LTTNG_EXPORT
void lttng_yyset_out(FILE *_out_str, yyscan_t yyscanner);
void lttng_yyset_out(FILE *_out_str, yyscan_t yyscanner)
{
	return yyset_out(_out_str, yyscanner);
}
