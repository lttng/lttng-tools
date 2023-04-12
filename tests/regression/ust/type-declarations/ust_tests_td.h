/*
 * Copyright (C) 2014 Geneviève Bastien <gbastien@versatic.net>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER ust_tests_td

#if !defined(_TRACEPOINT_UST_TESTS_TD_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_TESTS_TD_H

#include <lttng/tracepoint.h>

TRACEPOINT_ENUM(ust_tests_td,
		testenum,
		TP_ENUM_VALUES(ctf_enum_value("zero", 0) ctf_enum_value("one", 1)))

TRACEPOINT_ENUM(ust_tests_td,
		testenum2,
		TP_ENUM_VALUES(ctf_enum_value("zero", 0) ctf_enum_value("five", 5)
				       ctf_enum_range("ten_to_twenty", 10, 20)))

TRACEPOINT_ENUM(ust_tests_td,
		testenum3,
		TP_ENUM_VALUES(ctf_enum_auto("zero") ctf_enum_value("two", 2) ctf_enum_auto("three")
				       ctf_enum_range("ten_to_twenty", 10, 20)
					       ctf_enum_auto("twenty_one")))

/*
 * Enumeration field is used twice to make sure the global type declaration
 * is entered only once in the metadata file.
 */
TRACEPOINT_EVENT(
	ust_tests_td,
	tptest,
	TP_ARGS(int, enumval, int, enumval2, int, enumval3),
	TP_FIELDS(
		ctf_enum(ust_tests_td, testenum, int, enumfield, enumval) ctf_enum(
			ust_tests_td, testenum, long long, enumfield_bis, enumval2)
			ctf_enum(ust_tests_td, testenum2, unsigned int, enumfield_third, enumval3)))

/*
 * Another tracepoint using the global types to make sure each global type is
 * entered only once in the metadata file.
 */
TRACEPOINT_EVENT(ust_tests_td,
		 tptest_bis,
		 TP_ARGS(int, enumval),
		 TP_FIELDS(ctf_enum(ust_tests_td, testenum, unsigned char, enumfield, enumval)))

/*
 * Test autoincrementing enumeration values.
 */
TRACEPOINT_EVENT(ust_tests_td,
		 test_auto,
		 TP_ARGS(void),
		 TP_FIELDS(ctf_enum(ust_tests_td, testenum3, int, zero, 0) ctf_enum(
			 ust_tests_td, testenum3, int, two, 2)
				   ctf_enum(ust_tests_td, testenum3, int, three, 3) ctf_enum(
					   ust_tests_td, testenum3, int, fifteen, 15)
					   ctf_enum(ust_tests_td, testenum3, int, twenty_one, 21)))

#endif /* _TRACEPOINT_UST_TESTS_TD_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./ust_tests_td.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
