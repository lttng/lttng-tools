/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "backward-compatibility-group-by.hpp"
#include "common/time.hpp"

#include <common/common.hpp>
#include <common/defaults.hpp>
#include <common/utils.hpp>

#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DATETIME_REGEX ".*-[1-2][0-9][0-9][0-9][0-1][0-9][0-3][0-9]-[0-2][0-9][0-5][0-9][0-5][0-9]$"

/*
 * Provide support for --group-output-by-session for producer >= 2.4 and < 2.11.
 * Take the stream path, extract all available information, craft a new path to
 * the best of our ability enforcing the group by session.
 *
 * Return the allocated string containing the new stream path or else NULL.
 */
char *backward_compat_group_by_session(const char *path,
				       const char *local_session_name,
				       time_t relay_session_creation_time)
{
	int ret;
	size_t len;
	char *leftover_ptr;
	char *local_copy = NULL;
	char *datetime = NULL;
	char *partial_base_path = NULL;
	char *filepath_per_session = NULL;
	const char *second_token_ptr;
	const char *leftover_second_token_ptr;
	const char *hostname_ptr;
	regex_t regex;

	LTTNG_ASSERT(path);
	LTTNG_ASSERT(local_session_name);
	LTTNG_ASSERT(local_session_name[0] != '\0');

	DBG("Parsing path \"%s\" of session \"%s\" to create a new path that is grouped by session",
	    path,
	    local_session_name);

	/* Get a local copy for strtok */
	local_copy = strdup(path);
	if (!local_copy) {
		PERROR("Failed to parse session path: couldn't copy input path");
		goto error;
	}

	/*
	 * The use of strtok with '/' as delimiter is valid since we refuse '/'
	 * in session name and '/' is not a valid hostname character based on
	 * RFC-952 [1], RFC-921 [2] and refined in RFC-1123 [3].
	 * [1] https://tools.ietf.org/html/rfc952
	 * [2] https://tools.ietf.org/html/rfc921
	 * [3] https://tools.ietf.org/html/rfc1123#page-13
	 */

	/*
	 * Get the hostname and possible session_name.
	 * Note that we can get the hostname and session name from the
	 * relay_session object we already have. Still, it is easier to
	 * tokenized the passed path to obtain the start of the path leftover.
	 */
	hostname_ptr = strtok_r(local_copy, "/", &leftover_ptr);
	if (!hostname_ptr) {
		ERR("Failed to parse session path \"%s\": couldn't identify hostname", path);
		goto error;
	}

	second_token_ptr = strtok_r(NULL, "/", &leftover_ptr);
	if (!second_token_ptr) {
		ERR("Failed to parse session path \"%s\": couldn't identify session name", path);
		goto error;
	}

	/*
	 * Check if the second token is a base path set at url level. This is
	 * legal in streaming, live and snapshot [1]. Otherwise it is the
	 * session name with possibly a datetime attached [2]. Note that when
	 * "adding" snapshot output (lttng snapshot add-output), no session name
	 * is present in the path by default. The handling for "base path" take
	 * care of this case as well.
	 * [1] e.g --set-url net://localhost/my_marvellous_path
	 * [2] Can be:
	 *            <session_name>
	 *                When using --snapshot on session create.
	 *            <session_name>-<date>-<time>
	 *            <auto>-<date>-<time>
	 */
	if (strncmp(second_token_ptr, local_session_name, strlen(local_session_name)) != 0) {
		/*
		 * Token does not start with session name.
		 * This mean this is an extra path scenario.
		 * Duplicate the current token since it is part of an
		 * base_path.
		 * Set secDuplicate the current token since it is part of an
		 * base_path. The rest is the leftover.
		 * Set second_token_ptr to the local_session_name for further
		 * processing.
		 */
		partial_base_path = strdup(second_token_ptr);
		if (!partial_base_path) {
			PERROR("Failed to parse session path: couldn't copy partial base path");
			goto error;
		}

		second_token_ptr = local_session_name;
	}

	/*
	 * Based on the previous test, we can move inside the token ptr to
	 * remove the "local_session_name" and inspect the rest of the token.
	 * We are looking into extracting the creation datetime from either the
	 * session_name or the token. We need to to all this gymnastic because
	 * an extra path could decide to append a datetime to its first
	 * subdirectory.
	 * Possible scenario:
	 *     <session_name>
	 *     <session_name>-<date>-<time>
	 *     <auto>-<date>-<time>
	 *     <session_name>_base_path_foo_bar
	 *     <session_name>-<false date>-<false-time> (via a base path)
	 *
	 * We have no way to discern from the basic scenario of:
	 *     <session_name>-<date>-<time>
	 * and one done using a base path with the exact format we normally
	 * expect.
	 *
	 * e.g:
	 *     lttng create my_session -U
	 *         net://localhost/my_session-19910319-120000/
	 */
	ret = regcomp(&regex, DATETIME_REGEX, 0);
	if (ret) {
		ERR("Failed to parse session path: regex compilation failed with code %d", ret);
		goto error;
	}

	leftover_second_token_ptr = second_token_ptr + strlen(local_session_name);
	len = strlen(leftover_second_token_ptr);
	if (len == 0) {
		/*
		 * We are either dealing with an auto session name or only the
		 * session_name. If this is a auto session name, we need to
		 * fetch the creation datetime.
		 */
		ret = regexec(&regex, local_session_name, 0, NULL, 0);
		if (ret == 0) {
			const ssize_t local_session_name_offset =
				strlen(local_session_name) - DATETIME_STR_LEN + 1;

			LTTNG_ASSERT(local_session_name_offset >= 0);
			datetime = strdup(local_session_name + local_session_name_offset);
			if (!datetime) {
				PERROR("Failed to parse session path: couldn't copy datetime on regex match");
				goto error_regex;
			}
		} else {
			datetime = calloc<char>(DATETIME_STR_LEN);
			if (!datetime) {
				PERROR("Failed to allocate DATETIME string");
				goto error;
			}

			ret = time_to_datetime_str(
				relay_session_creation_time, datetime, DATETIME_STR_LEN);
			if (ret) {
				/* time_to_datetime_str already logs errors. */
				goto error;
			}
		}
	} else if (len == DATETIME_STR_LEN &&
		   !regexec(&regex, leftover_second_token_ptr, 0, NULL, 0)) {
		/*
		 * The leftover from the second token is of format
		 * "-<datetime>", use it as the creation time.
		 * Ignore leading "-".
		 */
		datetime = strdup(&leftover_second_token_ptr[1]);
		if (!datetime) {
			PERROR("Failed to parse session path: couldn't copy datetime on regex match");
			goto error_regex;
		}
	} else {
		/*
		 * Base path scenario.
		 * We cannot try to extract the datetime from the session name
		 * since nothing prevent a user to name a session in the
		 * "name-<datetime>" format. Using the datetime from such a
		 * session would be invalid.
		 * */
		LTTNG_ASSERT(partial_base_path == NULL);
		LTTNG_ASSERT(datetime == NULL);

		partial_base_path = strdup(second_token_ptr);
		if (!partial_base_path) {
			PERROR("Failed to parse session path: couldn't copy partial base path");
			goto error_regex;
		}
	}

	ret = asprintf(&filepath_per_session,
		       "%s/%s%s%s/%s%s%s",
		       local_session_name,
		       hostname_ptr,
		       datetime ? "-" : "",
		       datetime ? datetime : "",
		       partial_base_path ? partial_base_path : "",
		       partial_base_path ? "/" : "",
		       leftover_ptr);
	if (ret < 0) {
		filepath_per_session = NULL;
		goto error;
	}
error_regex:
	regfree(&regex);
error:
	free(local_copy);
	free(partial_base_path);
	free(datetime);
	return filepath_per_session;
}
