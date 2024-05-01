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

namespace lttng {
namespace libxml {

using parser_ctx_uptr = std::unique_ptr<
	xmlParserCtxt,
	lttng::memory::create_deleter_class<xmlParserCtxt, xmlFreeParserCtxt>::deleter>;
using doc_uptr =
	std::unique_ptr<xmlDoc, lttng::memory::create_deleter_class<xmlDoc, xmlFreeDoc>::deleter>;

/*
 * Manage the global parser context of libxml2.
 * There should only be one instance of this class per process.
 */
class global_parser_context {
public:
	global_parser_context()
	{
		xmlInitParser();
	}

	~global_parser_context()
	{
		xmlCleanupParser();
	}

	/* Deactivate copy and assignment. */
	global_parser_context(const global_parser_context&) = delete;
	global_parser_context(global_parser_context&&) = delete;
	global_parser_context& operator=(const global_parser_context&) = delete;
	global_parser_context& operator=(global_parser_context&&) = delete;
};
} /* namespace libxml */
} /* namespace lttng */
#endif /* TESTS_UTILS_XML_UTILS_COMMON_HPP */
