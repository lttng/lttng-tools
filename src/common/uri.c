/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <common/common.h>
#include <common/defaults.h>

#include "uri.h"

enum uri_proto_code {
	P_NET, P_NET6, P_FILE, P_TCP, P_TCP6,
};

struct uri_proto {
	char *name;
	enum uri_proto_code code;
	enum lttng_proto_type type;
	enum lttng_dst_type dtype;
};

/* Supported protocols */
static const struct uri_proto proto_uri[] = {
	{ .name = "file", .code = P_FILE, .type = 0, .dtype = LTTNG_DST_PATH},
	{ .name = "net", .code = P_NET, .type = LTTNG_TCP, .dtype = LTTNG_DST_IPV4 },
	{ .name = "net6", .code = P_NET6, .type = LTTNG_TCP, .dtype = LTTNG_DST_IPV6 },
	{ .name = "tcp", .code = P_TCP, .type = LTTNG_TCP, .dtype = LTTNG_DST_IPV4 },
	{ .name = "tcp6", .code = P_TCP6, .type = LTTNG_TCP, .dtype = LTTNG_DST_IPV6 },
	{ .name = NULL }
};

/*
 * Validate if proto is a supported protocol from proto_uri array.
 */
static const struct uri_proto *validate_protocol(char *proto)
{
	const struct uri_proto *supported;

	/* Safety net */
	if (proto == NULL) {
		goto end;
	}

	for (supported = &proto_uri[0];
			supported->name != NULL; ++supported) {
		if (strncmp(proto, supported->name, strlen(proto)) == 0) {
			goto end;
		}
	}

	/* Proto not found */
	return NULL;

end:
	return supported;
}

/*
 * Compare two URIs.
 *
 * Return 0 if equal else 1.
 */
int uri_compare(struct lttng_uri *uri1, struct lttng_uri *uri2)
{
	return memcmp(uri1, uri2, sizeof(struct lttng_uri));
}

/*
 * Free URI memory.
 */
void uri_free(struct lttng_uri *uri)
{
	/* Safety check */
	if (uri != NULL) {
		free(uri);
	}
}

/*
 * Return an allocated URI.
 */
struct lttng_uri *uri_create(void)
{
	struct lttng_uri *uri;

	uri = zmalloc(sizeof(struct lttng_uri));
	if (uri == NULL) {
		PERROR("zmalloc uri");
	}

	return uri;
}

static int set_ip_address(const char *addr, int af, char *dst, size_t size)
{
	int ret;
	unsigned char buf[sizeof(struct in6_addr)];
	struct hostent *record;

	/* Network protocol */
	ret = inet_pton(af, addr, buf);
	if (ret < 1) {
		/* We consider the dst to be an hostname or an invalid IP char */
		record = gethostbyname2(addr, af);
		if (record == NULL) {
			/* At this point, the IP or the hostname is bad */
			printf("bad hostname\n");
			goto error;
		}

		/* Translate IP to string */
		(void) inet_ntop(af, record->h_addr_list[0], dst, size);
	} else {
		memcpy(dst, addr, size);
	}

	return 0;

error:
	return -1;
}

ssize_t uri_parse(const char *str_uri, struct lttng_uri **uris)
{
	int ret;
	/* Size of the uris array. Default is 1 */
	ssize_t size = 1;
	char net[6], dst[LTTNG_MAX_DNNAME + 1];
	unsigned int ctrl_port = DEFAULT_NETWORK_CONTROL_PORT;
	unsigned int data_port = DEFAULT_NETWORK_DATA_PORT;
	struct lttng_uri *uri;
	const struct uri_proto *proto;

	/*
	 * The first part is the protocol portion of a maximum of 5 bytes for now.
	 * (tcp, tcp6, udp, udp6, file, net). The second part is the hostname or IP
	 * address. The 255 bytes size is the limit found in the RFC 1035 for the
	 * total length of a domain name (https://www.ietf.org/rfc/rfc1035.txt).
	 * Finally, with the net:// protocol, two ports can be specified.
	 */

	ret = sscanf(str_uri, "%5[^:]://", net);
	if (ret < 1) {
		printf("bad protocol\n");
		goto error;
	}

	DBG3("URI protocol : %s", str_uri);

	proto = validate_protocol(net);
	if (proto == NULL) {
		printf("no protocol\n");
		ret = -1;
		goto error;
	}

	if (proto->code == P_NET || proto->code == P_NET6) {
		/* Special case for net:// which requires two URI object */
		size = 2;
	}

	/* Parse the rest of the URI */
	ret = sscanf(str_uri + strlen(net), "://%255[^:]:%u:%u", dst,
			&ctrl_port, &data_port);
	if (ret < 0) {
		printf("bad URI\n");
		goto error;
	}

	/* We have enough valid information to create URI(s) object */

	/* Allocate URI array */
	uri = zmalloc(sizeof(struct lttng_uri) * size);
	if (uri == NULL) {
		PERROR("zmalloc uri");
		goto error;
	}

	/* Copy generic information */
	uri[0].dtype = proto->dtype;
	uri[0].proto = proto->type;
	uri[0].port = ctrl_port;

	DBG3("URI dtype: %d, proto: %d, port: %d", proto->dtype, proto->type,
			ctrl_port);

	switch (proto->code) {
	case P_FILE:
		memcpy(uri[0].dst.path, dst, sizeof(uri[0].dst.path));
		/* Reset port for the file:// URI */
		uri[0].port = 0;
		DBG3("URI file destination: %s", dst);
		break;
	case P_NET:
		ret = set_ip_address(dst, AF_INET, uri[0].dst.ipv4,
				sizeof(uri[0].dst.ipv4));
		if (ret < 0) {
			goto free_error;
		}

		memcpy(uri[1].dst.ipv4, uri[0].dst.ipv4, sizeof(uri[1].dst.ipv4));

		uri[1].dtype = proto->dtype;
		uri[1].proto = proto->type;
		uri[1].port = data_port;
		break;
	case P_NET6:
		ret = set_ip_address(dst, AF_INET6, uri[0].dst.ipv6,
				sizeof(uri[0].dst.ipv6));
		if (ret < 0) {
			goto free_error;
		}

		memcpy(uri[1].dst.ipv6, uri[0].dst.ipv6, sizeof(uri[1].dst.ipv6));

		uri[1].dtype = proto->dtype;
		uri[1].proto = proto->type;
		uri[1].port = data_port;
		break;
	case P_TCP:
		ret = set_ip_address(dst, AF_INET, uri[0].dst.ipv4,
				sizeof(uri[0].dst.ipv4));
		if (ret < 0) {
			goto free_error;
		}
		break;
	case P_TCP6:
		ret = set_ip_address(dst, AF_INET6, uri[0].dst.ipv6,
				sizeof(uri[0].dst.ipv6));
		if (ret < 0) {
			goto free_error;
		}
		break;
	default:
		goto free_error;
	}

	*uris = uri;

	return size;

free_error:
	free(uri);
error:
	return -1;
}
