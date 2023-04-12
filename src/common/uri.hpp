/*
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef URI_H
#define URI_H

#include <common/macros.hpp>

#include <lttng/lttng.h>

#include <netinet/in.h>

/* Destination type of lttng URI */
enum lttng_dst_type {
	LTTNG_DST_IPV4 = 1,
	LTTNG_DST_IPV6 = 2,
	LTTNG_DST_PATH = 3,
};

/* Type of lttng URI where it is a final destination or a hop */
enum lttng_uri_type {
	LTTNG_URI_DST, /* The URI is a final destination */
	/*
	 * Hops are not supported yet but planned for a future release.
	 *
	 LTTNG_URI_HOP,
	 */
};

/* Communication stream type of a lttng URI */
enum lttng_stream_type {
	LTTNG_STREAM_CONTROL,
	LTTNG_STREAM_DATA,
};

/*
 * Protocol type of a lttng URI. The value 0 indicate that the proto_type field
 * should be ignored.
 */
enum lttng_proto_type {
	LTTNG_PROTO_TYPE_NONE = 0,
	LTTNG_TCP = 1,
	/*
	 * UDP protocol is not supported for now.
	 *
	 LTTNG_UDP                             = 2,
	 */
};

/*
 * Structure representing an URI supported by lttng.
 */
struct lttng_uri {
	enum lttng_dst_type dtype;
	enum lttng_uri_type utype;
	enum lttng_stream_type stype;
	enum lttng_proto_type proto;
	uint16_t port;
	char subdir[LTTNG_PATH_MAX];
	union {
		char ipv4[INET_ADDRSTRLEN];
		char ipv6[INET6_ADDRSTRLEN];
		char path[LTTNG_PATH_MAX];
	} dst;
} LTTNG_PACKED;

int uri_compare(struct lttng_uri *uri1, struct lttng_uri *uri2);
void uri_free(struct lttng_uri *uri);
ssize_t uri_parse(const char *str_uri, struct lttng_uri **uris);
ssize_t uri_parse_str_urls(const char *ctrl_url, const char *data_url, struct lttng_uri **uris);
int uri_to_str_url(struct lttng_uri *uri, char *dst, size_t size);

#endif /* _LTT_URI_H */
