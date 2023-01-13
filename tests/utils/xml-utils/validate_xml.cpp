/*
 * Copyright (C) 2014 EfficiOS Inc.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

/*
 * This script validate and xml from an xsd.
 * argv[1] Path of the xsd
 * argv[2] Path to the XML to be validated
 */

#include <common/macros.hpp>

#include <lttng/lttng-error.h>

#include <ctype.h>
#include <dirent.h>
#include <inttypes.h>
#include <libxml/parser.h>
#include <libxml/xmlschemas.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace {
struct validation_ctx {
	xmlSchemaParserCtxtPtr parser_ctx;
	xmlSchemaPtr schema;
	xmlSchemaValidCtxtPtr schema_validation_ctx;
};
} /* namespace */

enum command_err_code { CMD_SUCCESS = 0, CMD_ERROR };

static ATTR_FORMAT_PRINTF(2, 3) void xml_error_handler(void *ctx __attribute__((unused)),
						       const char *format,
						       ...)
{
	char *err_msg;
	va_list args;
	int ret;

	va_start(args, format);
	ret = vasprintf(&err_msg, format, args);
	va_end(args);
	if (ret == -1) {
		fprintf(stderr, "ERR: %s\n", "String allocation failed in xml error handle");
		return;
	}

	fprintf(stderr, "XML Error: %s\n", err_msg);
	free(err_msg);
}

static void fini_validation_ctx(struct validation_ctx *ctx)
{
	if (ctx->parser_ctx) {
		xmlSchemaFreeParserCtxt(ctx->parser_ctx);
	}

	if (ctx->schema) {
		xmlSchemaFree(ctx->schema);
	}

	if (ctx->schema_validation_ctx) {
		xmlSchemaFreeValidCtxt(ctx->schema_validation_ctx);
	}

	memset(ctx, 0, sizeof(struct validation_ctx));
}

static int init_validation_ctx(struct validation_ctx *ctx, char *xsd_path)
{
	int ret;

	if (!xsd_path) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	ctx->parser_ctx = xmlSchemaNewParserCtxt(xsd_path);
	if (!ctx->parser_ctx) {
		ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
		goto end;
	}
	xmlSchemaSetParserErrors(ctx->parser_ctx, xml_error_handler, xml_error_handler, NULL);

	ctx->schema = xmlSchemaParse(ctx->parser_ctx);
	if (!ctx->schema) {
		ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
		goto end;
	}

	ctx->schema_validation_ctx = xmlSchemaNewValidCtxt(ctx->schema);
	if (!ctx->schema_validation_ctx) {
		ret = -LTTNG_ERR_LOAD_INVALID_CONFIG;
		goto end;
	}

	xmlSchemaSetValidErrors(
		ctx->schema_validation_ctx, xml_error_handler, xml_error_handler, NULL);
	ret = 0;

end:
	if (ret) {
		fini_validation_ctx(ctx);
	}
	return ret;
}

static int validate_xml(const char *xml_file_path, struct validation_ctx *ctx)
{
	int ret;
	xmlDocPtr doc = NULL;

	LTTNG_ASSERT(xml_file_path);
	LTTNG_ASSERT(ctx);

	/* Open the document */
	doc = xmlParseFile(xml_file_path);
	if (!doc) {
		ret = LTTNG_ERR_MI_IO_FAIL;
		goto end;
	}

	/* Validate against the validation ctx (xsd) */
	ret = xmlSchemaValidateDoc(ctx->schema_validation_ctx, doc);
	if (ret) {
		fprintf(stderr, "ERR: %s\n", "XML is not valid againt provided XSD");
		ret = CMD_ERROR;
		goto end;
	}

	ret = CMD_SUCCESS;
end:
	if (doc) {
		xmlFreeDoc(doc);
	}
	return ret;
}

int main(int argc, char **argv)
{
	int ret;
	struct validation_ctx ctx = {};

	/* Check if we have all argument */
	if (argc < 3) {
		fprintf(stderr, "ERR: %s\n", "Missing arguments");
		ret = CMD_ERROR;
		goto end;
	}

	/* Check if xsd file exist */
	ret = access(argv[1], F_OK);
	if (ret < 0) {
		fprintf(stderr, "ERR: %s\n", "Xsd path not valid");
		goto end;
	}

	/* Check if xml to validate exist */
	ret = access(argv[2], F_OK);
	if (ret < 0) {
		fprintf(stderr, "ERR: %s\n", "XML path not valid");
		goto end;
	}

	/* initialize the validation ctx */
	ret = init_validation_ctx(&ctx, argv[1]);
	if (ret) {
		goto end;
	}

	ret = validate_xml(argv[2], &ctx);

	fini_validation_ctx(&ctx);

end:
	return ret;
}
