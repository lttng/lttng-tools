/*
 * Copyright (C) 2021 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

/*
 * Prettyfi a xml input from stdin to stddout.
 * This allows a more human friendly format for xml testing when problems occur.
 */

#include "common.hpp"

#include <libxml/parser.h>
#include <unistd.h>

int main()
{
	xmlDocPtr doc = NULL;

	/* Init libxml. */
	xmlInitParser();

	{
		xml_parser_ctx_uptr parserCtx{ xmlNewParserCtxt() };

		/* Parse the XML document from stdin. */
		doc = xmlCtxtReadFd(
			parserCtx.get(), STDIN_FILENO, nullptr, nullptr, XML_PARSE_NOBLANKS);
		if (!doc) {
			fprintf(stderr, "ERR parsing: xml input invalid");
			return -1;
		}

		xmlDocFormatDump(stdout, doc, 1);

		xmlFreeDoc(doc);
	}

	/* Shutdown libxml. */
	xmlCleanupParser();

	return 0;
}
