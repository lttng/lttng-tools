/*
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2013 Raphaël Beamonte <raphael.beamonte@gmail.com>
 * Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright (C) 2021 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define _LGPL_SOURCE
#include <common/common.hpp>
#include <common/macros.hpp>
#include <common/path.hpp>

/*
 * Return a partial realpath(3) of the path even if the full path does not
 * exist. For instance, with /tmp/test1/test2/test3, if test2/ does not exist
 * but the /tmp/test1 does, the real path for /tmp/test1 is concatened with
 * /test2/test3 then returned. In normal time, realpath(3) fails if the end
 * point directory does not exist.
 *
 * Return a newly-allocated string.
 */
char *utils_partial_realpath(const char *path)
{
	char *cut_path = nullptr, *try_path = nullptr, *try_path_prev = nullptr;
	const char *next, *prev, *end;
	char *resolved_path = nullptr;

	/* Safety net */
	if (path == nullptr) {
		goto error;
	}

	/*
	 * Identify the end of the path, we don't want to treat the
	 * last char if it is a '/', we will just keep it on the side
	 * to be added at the end, and return a value coherent with
	 * the path given as argument
	 */
	end = path + strlen(path);
	if (*(end - 1) == '/') {
		end--;
	}

	/* Initiate the values of the pointers before looping */
	next = path;
	prev = next;
	/* Only to ensure try_path is not NULL to enter the while */
	try_path = (char *) next;

	/* Resolve the canonical path of the first part of the path */
	while (try_path != nullptr && next != end) {
		char *try_path_buf = nullptr;

		/*
		 * If there is not any '/' left, we want to try with
		 * the full path
		 */
		next = strpbrk(next + 1, "/");
		if (next == nullptr) {
			next = end;
		}

		/* Cut the part we will be trying to resolve */
		cut_path = lttng_strndup(path, next - path);
		if (cut_path == nullptr) {
			PERROR("lttng_strndup");
			goto error;
		}

		try_path_buf = zmalloc<char>(LTTNG_PATH_MAX);
		if (!try_path_buf) {
			PERROR("zmalloc");
			goto error;
		}

		/* Try to resolve this part */
		try_path = realpath((char *) cut_path, try_path_buf);
		if (try_path == nullptr) {
			free(try_path_buf);
			/*
			 * There was an error, we just want to be assured it
			 * is linked to an unexistent directory, if it's another
			 * reason, we spawn an error
			 */
			switch (errno) {
			case ENOENT:
				/* Ignore the error */
				break;
			default:
				PERROR("realpath (partial_realpath)");
				goto error;
				break;
			}
		} else {
			/* Save the place we are before trying the next step */
			try_path_buf = nullptr;
			free(try_path_prev);
			try_path_prev = try_path;
			prev = next;
		}

		/* Free the allocated memory */
		free(cut_path);
		cut_path = nullptr;
	}

	/* Allocate memory for the resolved path. */
	resolved_path = zmalloc<char>(LTTNG_PATH_MAX);
	if (resolved_path == nullptr) {
		PERROR("zmalloc resolved path");
		goto error;
	}

	/*
	 * If we were able to solve at least partially the path, we can concatenate
	 * what worked and what didn't work
	 */
	if (try_path_prev != nullptr) {
		/* If we risk to concatenate two '/', we remove one of them */
		if (try_path_prev[strlen(try_path_prev) - 1] == '/' && prev[0] == '/') {
			try_path_prev[strlen(try_path_prev) - 1] = '\0';
		}

		/*
		 * Duplicate the memory used by prev in case resolved_path and
		 * path are pointers for the same memory space
		 */
		cut_path = strdup(prev);
		if (cut_path == nullptr) {
			PERROR("strdup");
			goto error;
		}

		/* Concatenate the strings */
		const auto snprintf_ret =
			snprintf(resolved_path, LTTNG_PATH_MAX, "%s%s", try_path_prev, cut_path);
		if (snprintf_ret >= LTTNG_PATH_MAX) {
			ERR("Path exceeded maximal allowed length while determining canonicalized absolute pathname");
			goto error;
		}

		/* Free the allocated memory */
		free(cut_path);
		free(try_path_prev);
		cut_path = nullptr;
		try_path_prev = nullptr;
		/*
		 * Else, we just copy the path in our resolved_path to
		 * return it as is
		 */
	} else {
		strncpy(resolved_path, path, LTTNG_PATH_MAX);
	}

	/* Then we return the 'partially' resolved path */
	return resolved_path;

error:
	free(resolved_path);
	free(cut_path);
	free(try_path);
	if (try_path_prev != try_path) {
		free(try_path_prev);
	}
	return nullptr;
}

static int expand_double_slashes_dot_and_dotdot(char *path)
{
	size_t expanded_path_len, path_len;
	const char *curr_char, *path_last_char, *next_slash, *prev_slash;

	path_len = strlen(path);
	path_last_char = &path[path_len];

	if (path_len == 0) {
		goto error;
	}

	expanded_path_len = 0;

	/* We iterate over the provided path to expand the "//", "../" and "./" */
	for (curr_char = path; curr_char <= path_last_char; curr_char = next_slash + 1) {
		/* Find the next forward slash. */
		size_t curr_token_len;

		if (curr_char == path_last_char) {
			expanded_path_len++;
			break;
		}

		next_slash = (const char *) memchr(curr_char, '/', path_last_char - curr_char);
		if (next_slash == nullptr) {
			/* Reached the end of the provided path. */
			next_slash = path_last_char;
		}

		/* Compute how long is the previous token. */
		curr_token_len = next_slash - curr_char;
		switch (curr_token_len) {
		case 0:
			/*
			 * The pointer has not move meaning that curr_char is
			 * pointing to a slash. It that case there is no token
			 * to copy, so continue the iteration to find the next
			 * token
			 */
			continue;
		case 1:
			/*
			 * The pointer moved 1 character. Check if that
			 * character is a dot ('.'), if it is: omit it, else
			 * copy the token to the normalized path.
			 */
			if (curr_char[0] == '.') {
				continue;
			}
			break;
		case 2:
			/*
			 * The pointer moved 2 characters. Check if these
			 * characters are double dots ('..'). If that is the
			 * case, we need to remove the last token of the
			 * normalized path.
			 */
			if (curr_char[0] == '.' && curr_char[1] == '.') {
				/*
				 * Find the previous path component by
				 * using the memrchr function to find the
				 * previous forward slash and substract that
				 * len to the resulting path.
				 */
				prev_slash =
					(const char *) lttng_memrchr(path, '/', expanded_path_len);
				/*
				 * If prev_slash is NULL, we reached the
				 * beginning of the path. We can't go back any
				 * further.
				 */
				if (prev_slash != nullptr) {
					expanded_path_len = prev_slash - path;
				}
				continue;
			}
			break;
		default:
			break;
		}

		/*
		 * Copy the current token which is neither a '.' nor a '..'.
		 */
		path[expanded_path_len++] = '/';
		memmove(&path[expanded_path_len], curr_char, curr_token_len);
		expanded_path_len += curr_token_len;
	}

	if (expanded_path_len == 0) {
		path[expanded_path_len++] = '/';
	}

	path[expanded_path_len] = '\0';
	return 0;
error:
	return -1;
}

/*
 * Make a full resolution of the given path even if it doesn't exist.
 * This function uses the utils_partial_realpath function to resolve
 * symlinks and relatives paths at the start of the string, and
 * implements functionnalities to resolve the './' and '../' strings
 * in the middle of a path. This function is only necessary because
 * realpath(3) does not accept to resolve unexistent paths.
 * The returned string was allocated in the function, it is thus of
 * the responsibility of the caller to free this memory.
 */
static char *_utils_expand_path(const char *path, bool keep_symlink)
{
	int ret;
	char *absolute_path = nullptr;
	char *last_token;
	bool is_dot, is_dotdot;

	/* Safety net */
	if (path == nullptr) {
		goto error;
	}

	/* Allocate memory for the absolute_path */
	absolute_path = zmalloc<char>(LTTNG_PATH_MAX);
	if (absolute_path == nullptr) {
		PERROR("zmalloc expand path");
		goto error;
	}

	if (path[0] == '/') {
		ret = lttng_strncpy(absolute_path, path, LTTNG_PATH_MAX);
		if (ret) {
			ERR("Path exceeds maximal size of %i bytes", LTTNG_PATH_MAX);
			goto error;
		}
	} else {
		/*
		 * This is a relative path. We need to get the present working
		 * directory and start the path walk from there.
		 */
		char current_working_dir[LTTNG_PATH_MAX];
		char *cwd_ret;

		cwd_ret = getcwd(current_working_dir, sizeof(current_working_dir));
		if (!cwd_ret) {
			goto error;
		}
		/*
		 * Get the number of character in the CWD and allocate an array
		 * to can hold it and the path provided by the caller.
		 */
		ret = snprintf(absolute_path, LTTNG_PATH_MAX, "%s/%s", current_working_dir, path);
		if (ret >= LTTNG_PATH_MAX) {
			ERR("Concatenating current working directory %s and path %s exceeds maximal size of %i bytes",
			    current_working_dir,
			    path,
			    LTTNG_PATH_MAX);
			goto error;
		}
	}

	if (keep_symlink) {
		/* Resolve partially our path */
		char *new_absolute_path = utils_partial_realpath(absolute_path);
		if (!new_absolute_path) {
			goto error;
		}

		free(absolute_path);
		absolute_path = new_absolute_path;
	}

	ret = expand_double_slashes_dot_and_dotdot(absolute_path);
	if (ret) {
		goto error;
	}

	/* Identify the last token */
	last_token = strrchr(absolute_path, '/');

	/* Verify that this token is not a relative path */
	is_dotdot = (strcmp(last_token, "/..") == 0);
	is_dot = (strcmp(last_token, "/.") == 0);

	/* If it is, take action */
	if (is_dot || is_dotdot) {
		/* For both, remove this token */
		*last_token = '\0';

		/* If it was a reference to parent directory, go back one more time */
		if (is_dotdot) {
			last_token = strrchr(absolute_path, '/');

			/* If there was only one level left, we keep the first '/' */
			if (last_token == absolute_path) {
				last_token++;
			}

			*last_token = '\0';
		}
	}

	return absolute_path;

error:
	free(absolute_path);
	return nullptr;
}
char *utils_expand_path(const char *path)
{
	return _utils_expand_path(path, true);
}

char *utils_expand_path_keep_symlink(const char *path)
{
	return _utils_expand_path(path, false);
}
