/*
 * Copyright (C) 2021 Jonathan Rajotte <jonathan.r.julien@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

/*
 * Prettyfi a xml input from stdin to stddout.
 * This allows a more human friendly format for xml testing when problems occur.
 */

#include <libxml/parser.h>

int main(int argc, char **argv)
{
	xmlDocPtr doc = NULL;

	/* Init libxml. */
	xmlInitParser();
	xmlKeepBlanksDefault(0);

	/* Parse the XML document from stdin. */
	doc = xmlParseFile("-");
	if (!doc) {
		fprintf(stderr, "ERR parsing: xml input invalid");
		return -1;
	}

	xmlDocFormatDump(stdout, doc, 1);

	xmlFreeDoc(doc);
	/* Shutdown libxml. */
	xmlCleanupParser();

	return 0;
}
