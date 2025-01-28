/*
 * SPDX-FileCopyrightText: 2021 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

/*
 * Prettyfi a xml input from stdin to stddout.
 * This allows a more human friendly format for xml testing when problems occur.
 */

#include "common.hpp"

#include <common/scope-exit.hpp>

#include <iostream>
#include <libxml/parser.h>
#include <unistd.h>

namespace ll = lttng::libxml;

int main()
{
	const ll::global_parser_context global_parser_context;
	const ll::parser_ctx_uptr parserCtx{ xmlNewParserCtxt() };

	/* Parse the XML document from stdin. */
	const ll::doc_uptr doc{ xmlCtxtReadFd(
		parserCtx.get(), STDIN_FILENO, nullptr, nullptr, XML_PARSE_NOBLANKS) };
	if (!doc) {
		std::cerr << "Error: invalid XML input on stdin\n";
		return -1;
	}

	xmlDocFormatDump(stdout, doc.get(), 1);

	return 0;
}
