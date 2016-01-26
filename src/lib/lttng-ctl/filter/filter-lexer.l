%{
/*
 * filter-lexer.l
 *
 * LTTng filter lexer
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
 */

#include <stdio.h>
#include "filter-ast.h"
#include "filter-parser.h"

extern
void setstring(struct filter_parser_ctx *parser_ctx, YYSTYPE *lvalp, const char *src);

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
ID_EXTRA_CHAR			(":"|".")
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
