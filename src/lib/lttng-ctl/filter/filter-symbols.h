#ifndef _FILTER_SYMBOLS_H
#define _FILTER_SYMBOLS_H

/*
 * filter-symbols.h
 *
 * LTTng filter flex/bison symbol prefixes
 *
 * Copyright 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define yy_create_buffer lttng_yy_create_buffer
#define yy_delete_buffer lttng_yy_delete_buffer
#define yy_flush_buffer lttng_yy_flush_buffer
#define yy_scan_buffer lttng_yy_scan_buffer
#define yy_scan_bytes lttng_yy_scan_bytes
#define yy_scan_string lttng_yy_scan_string
#define yy_switch_to_buffer lttng_yy_switch_to_buffer
#define yyalloc lttng_yyalloc
#define yyfree lttng_yyfree
#define yyget_column lttng_yyget_column
#define yyget_debug lttng_yyget_debug
#define yyget_extra lttng_yyget_extra
#define yyget_in lttng_yyget_in
#define yyget_leng lttng_yyget_leng
#define yyget_lineno lttng_yyget_lineno
#define yyget_lval lttng_yyget_lval
#define yyget_out lttng_yyget_out
#define yyget_text lttng_yyget_text
#define yylex_init lttng_yylex_init
#define yypop_buffer_state lttng_yypop_buffer_state
#define yypush_buffer_state lttng_yypush_buffer_state
#define yyrealloc lttng_yyrealloc
#define yyset_column lttng_yyset_column
#define yyset_debug lttng_yyset_debug
#define yyset_extra lttng_yyset_extra
#define yyset_in lttng_yyset_in
#define yyset_lineno lttng_yyset_lineno
#define yyset_lval lttng_yyset_lval
#define yyset_out lttng_yyset_out

#endif /* _FILTER_SYMBOLS_H */
