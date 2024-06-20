/*
 * Copyright (C) 2014 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

/*
 * Usage: extract_xml [-v|-e] xml_path xpath_expression
 * Evaluate XPath expression and prints result node set.
 * args[1] path to the xml file
 * args[2] xpath expression to extract
 * If -e look if node exist return "true" else nothing
 * If -v is set the name of the node will appear with his value delimited by
 * a semicolon(;)
 * Ex:
 * Command:extract_xml ../file.xml /test/node/text()
 * Output:
 *     a
 *     b
 *     c
 * With -v
 *     node;a;
 *     node;b;
 *     node;c;
 */
#include "common.hpp"

#include <common/defaults.hpp>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

namespace ll = lttng::libxml;

#if defined(LIBXML_XPATH_ENABLED)

static int opt_verbose;
static int node_exist;
static bool result = false;

/**
 * print_xpath_nodes:
 * nodes:  the nodes set.
 * output: the output file handle.
 *
 * Print the node content to the file
 */
static int print_xpath_nodes(xmlDocPtr doc, xmlNodeSetPtr nodes, FILE *output)
{
	int ret = 0;
	int size;
	int i;

	xmlNodePtr cur;
	xmlChar *node_child_value_string = nullptr;

	LTTNG_ASSERT(output);
	size = (nodes) ? nodes->nodeNr : 0;

	for (i = 0; i < size; ++i) {
		LTTNG_ASSERT(nodes->nodeTab[i]);

		if (nodes->nodeTab[i]->type == XML_NAMESPACE_DECL) {
			fprintf(stderr,
				"ERR:%s\n",
				"This executable does not support xml namespacing\n");
			ret = -1;
			goto end;
		} else if (nodes->nodeTab[i]->type == XML_ELEMENT_NODE) {
			cur = nodes->nodeTab[i];

			if (xmlChildElementCount(cur) == 0) {
				if (xmlNodeIsText(cur->children)) {
					node_child_value_string =
						xmlNodeListGetString(doc, cur->children, 1);
					if (node_exist) {
						result = true;
					} else if (opt_verbose) {
						fprintf(output,
							"%s;%s;\n",
							cur->name,
							node_child_value_string);
					} else {
						fprintf(output, "%s\n", node_child_value_string);
					}
					xmlFree(node_child_value_string);
				} else {
					/* We don't want to print non-final element */
					if (node_exist) {
						result = true;
					} else {
						fprintf(stderr,
							"ERR:%s\n",
							"Xpath expression return non-final xml element");
						ret = -1;
						goto end;
					}
				}
			} else {
				if (node_exist) {
					result = true;
				} else {
					/* We don't want to print non-final element */
					fprintf(stderr,
						"ERR:%s\n",
						"Xpath expression return non-final xml element");
					ret = -1;
					goto end;
				}
			}

		} else {
			cur = nodes->nodeTab[i];
			if (node_exist) {
				result = true;
			} else if (opt_verbose) {
				fprintf(output, "%s;%s;\n", cur->parent->name, cur->content);
			} else {
				fprintf(output, "%s\n", cur->content);
			}
		}
	}
	/* Command Success */
	ret = 0;

end:
	return ret;
}

static int register_lttng_namespace(xmlXPathContextPtr xpathCtx)
{
	int ret;
	xmlChar *prefix;
	xmlChar *ns = nullptr;

	prefix = xmlCharStrdup("lttng");
	if (!prefix) {
		ret = -1;
		goto end;
	}

	ns = xmlCharStrdup(DEFAULT_LTTNG_MI_NAMESPACE);
	if (!ns) {
		ret = -1;
		goto end;
	}

	ret = xmlXPathRegisterNs(xpathCtx, prefix, ns);
end:
	xmlFree(prefix);
	xmlFree(ns);
	return ret;
}

/*
 * Extract element corresponding to xpath
 * xml_path     The path to the xml file
 * xpath:       The xpath to evaluate.
 *
 * Evaluate an xpath expression onto an xml file.
 * and print the result one by line.
 *
 * Returns 0 on success and a negative value otherwise.
 */
static int extract_xpath(const char *xml_path, const xmlChar *xpath)
{
	int ret;
	xmlDocPtr doc = nullptr;
	xmlXPathContextPtr xpathCtx = nullptr;
	xmlXPathObjectPtr xpathObj = nullptr;

	LTTNG_ASSERT(xml_path);
	LTTNG_ASSERT(xpath);

	const ll::parser_ctx_uptr parserCtx{ xmlNewParserCtxt() };

	if (!parserCtx) {
		fprintf(stderr, "ERR: could not allocate an XML parser context\n");
		return -1;
	}

	/* Parse the xml file */
	doc = xmlCtxtReadFile(parserCtx.get(), xml_path, nullptr, XML_PARSE_NOBLANKS);
	if (!doc) {
		fprintf(stderr, "ERR parsing: xml file invalid \"%s\"\n", xml_path);
		return -1;
	}

	/* Initialize a xpath context */
	xpathCtx = xmlXPathNewContext(doc);
	if (!xpathCtx) {
		fprintf(stderr, "ERR: XPath context invalid\n");
		xmlFreeDoc(doc);
		return -1;
	}

	/* Register the LTTng MI namespace */
	ret = register_lttng_namespace(xpathCtx);
	if (ret) {
		fprintf(stderr, "ERR: Could not register lttng namespace\n");
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return -1;
	}

	/* Evaluate xpath expression */
	xpathObj = xmlXPathEvalExpression(xpath, xpathCtx);
	if (!xpathObj) {
		fprintf(stderr, "ERR: invalid xpath expression \"%s\"\n", xpath);
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return -1;
	}

	/* Print results */
	if (print_xpath_nodes(doc, xpathObj->nodesetval, stdout)) {
		xmlXPathFreeObject(xpathObj);
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return -1;
	}
	if (node_exist && result) {
		fprintf(stdout, "true\n");
	}

	/* Cleanup */
	xmlXPathFreeObject(xpathObj);
	xmlXPathFreeContext(xpathCtx);
	xmlFreeDoc(doc);

	return 0;
}

int main(int argc, char **argv)
{
	int opt;

	/* Parse command line and process file */
	while ((opt = getopt(argc, argv, "ve")) != -1) {
		switch (opt) {
		case 'v':
			opt_verbose = 1;
			break;
		case 'e':
			node_exist = 1;
			break;
		default:
			abort();
		}
	}

	if (!(optind + 1 < argc)) {
		fprintf(stderr, "ERR:%s\n", "Arguments missing");
		return -1;
	}

	/* Init libxml */
	xmlInitParser();
	if (access(argv[optind], F_OK)) {
		fprintf(stderr, "ERR:%s\n", "Xml path not valid");
		return -1;
	}
	/* Do the main job */
	if (extract_xpath(argv[optind], (xmlChar *) argv[optind + 1])) {
		return -1;
	}

	/* Shutdown libxml */
	xmlCleanupParser();

	return 0;
}

#else
int main(void)
{
	fprintf(stderr, "XPath support not compiled in\n");
	return -1;
}
#endif
