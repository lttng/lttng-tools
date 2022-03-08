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

#include <libxml/parser.h>

int main(void)
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
