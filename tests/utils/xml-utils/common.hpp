/*
 * Copyright (C) 2024 EfficiOS Inc.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef TESTS_UTILS_XML_UTILS_COMMON_HPP
#define TESTS_UTILS_XML_UTILS_COMMON_HPP

#include "common/make-unique-wrapper.hpp"

#include <libxml/parser.h>
#include <memory>

using xml_parser_ctx_uptr = std::unique_ptr<
	xmlParserCtxt,
	lttng::memory::create_deleter_class<xmlParserCtxt, xmlFreeParserCtxt>::deleter>;

#endif /* TESTS_UTILS_XML_UTILS_COMMON_HPP */
