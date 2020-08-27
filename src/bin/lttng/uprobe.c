/*
 * Copyright (C) 2020 EfficiOS, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "uprobe.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/compat/getenv.h"
#include "common/string-utils/string-utils.h"
#include "common/utils.h"
#include "lttng/constant.h"

#include "command.h"

/*
 * Walk the directories in the PATH environment variable to find the target
 * binary passed as parameter.
 *
 * On success, the full path of the binary is copied in binary_full_path out
 * parameter. This buffer is allocated by the caller and must be at least
 * LTTNG_PATH_MAX bytes long.
 * On failure, returns -1;
 */
static
int walk_command_search_path(const char *binary, char *binary_full_path)
{
	char *tentative_binary_path = NULL;
	char *command_search_path = NULL;
	char *curr_search_dir_end = NULL;
	char *curr_search_dir = NULL;
	struct stat stat_output;
	int ret = 0;

	command_search_path = lttng_secure_getenv("PATH");
	if (!command_search_path) {
		ret = -1;
		goto end;
	}

	/*
	 * Duplicate the $PATH string as the char pointer returned by getenv() should
	 * not be modified.
	 */
	command_search_path = strdup(command_search_path);
	if (!command_search_path) {
		ret = -1;
		goto end;
	}

	/*
	 * This char array is used to concatenate path to binary to look for
	 * the binary.
	 */
	tentative_binary_path = zmalloc(LTTNG_PATH_MAX * sizeof(char));
	if (!tentative_binary_path) {
		ret = -1;
		goto alloc_error;
	}

	curr_search_dir = command_search_path;
	do {
		/*
		 * Split on ':'. The return value of this call points to the
		 * matching character.
		 */
		curr_search_dir_end = strchr(curr_search_dir, ':');
		if (curr_search_dir_end != NULL) {
			/*
			 * Add a NULL byte to the end of the first token so it
			 * can be used as a string.
			 */
			curr_search_dir_end[0] = '\0';
		}

		/* Empty the tentative path */
		memset(tentative_binary_path, 0, LTTNG_PATH_MAX * sizeof(char));

		/*
		 * Build the tentative path to the binary using the current
		 * search directory and the name of the binary.
		 */
		ret = snprintf(tentative_binary_path, LTTNG_PATH_MAX, "%s/%s",
				curr_search_dir, binary);
		if (ret < 0) {
			goto free_binary_path;
		}
		if (ret < LTTNG_PATH_MAX) {
			 /*
			  * Use STAT(2) to see if the file exists.
			 */
			ret = stat(tentative_binary_path, &stat_output);
			if (ret == 0) {
				/*
				 * Verify that it is a regular file or a
				 * symlink and not a special file (e.g.
				 * device).
				 */
				if (S_ISREG(stat_output.st_mode)
						|| S_ISLNK(stat_output.st_mode)) {
					/*
					 * Found a match, set the out parameter
					 * and return success.
					 */
					ret = lttng_strncpy(binary_full_path,
							tentative_binary_path,
							LTTNG_PATH_MAX);
					if (ret == -1) {
						ERR("Source path does not fit "
							"in destination buffer.");
					}
					goto free_binary_path;
				}
			}
		}
		/* Go to the next entry in the $PATH variable. */
		curr_search_dir = curr_search_dir_end + 1;
	} while (curr_search_dir_end != NULL);

free_binary_path:
	free(tentative_binary_path);
alloc_error:
	free(command_search_path);
end:
	return ret;
}

/*
 * Check if the symbol field passed by the user is in fact an address or an
 * offset from a symbol. Those two instrumentation types are not supported yet.
 * It's expected to be a common mistake because of the existing --probe option
 * that does support these formats.
 *
 * Here are examples of these unsupported formats for the --userspace-probe
 * option:
 * elf:/path/to/binary:0x400430
 * elf:/path/to/binary:4194364
 * elf:/path/to/binary:my_symbol+0x323
 * elf:/path/to/binary:my_symbol+43
 */
static
int warn_userspace_probe_syntax(const char *symbol)
{
	int ret;

	/* Check if the symbol field is an hex address. */
	ret = sscanf(symbol, "0x%*x");
	if (ret > 0) {
		/* If there is a match, print a warning and return an error. */
		ERR("Userspace probe on address not supported yet.");
		ret = CMD_UNSUPPORTED;
		goto error;
	}

	/* Check if the symbol field is an decimal address. */
	ret = sscanf(symbol, "%*u");
	if (ret > 0) {
		/* If there is a match, print a warning and return an error. */
		ERR("Userspace probe on address not supported yet.");
		ret = CMD_UNSUPPORTED;
		goto error;
	}

	/* Check if the symbol field is symbol+hex_offset. */
	ret = sscanf(symbol, "%*[^+]+0x%*x");
	if (ret > 0) {
		/* If there is a match, print a warning and return an error. */
		ERR("Userspace probe on symbol+offset not supported yet.");
		ret = CMD_UNSUPPORTED;
		goto error;
	}

	/* Check if the symbol field is symbol+decimal_offset. */
	ret = sscanf(symbol, "%*[^+]+%*u");
	if (ret > 0) {
		/* If there is a match, print a warning and return an error. */
		ERR("Userspace probe on symbol+offset not supported yet.");
		ret = CMD_UNSUPPORTED;
		goto error;
	}

	ret = 0;

error:
	return ret;
}

/*
 * Parse userspace probe options
 * Set the userspace probe fields in the lttng_event struct and set the
 * target_path to the path to the binary.
 */
LTTNG_HIDDEN
int parse_userspace_probe_opts(const char *opt,
		struct lttng_userspace_probe_location **probe_location)
{
	int ret = CMD_SUCCESS;
	int num_token;
	char **tokens = NULL;
	char *target_path = NULL;
	char *unescaped_target_path = NULL;
	char *real_target_path = NULL;
	char *symbol_name = NULL, *probe_name = NULL, *provider_name = NULL;
	struct lttng_userspace_probe_location *probe_location_local = NULL;
	struct lttng_userspace_probe_location_lookup_method *lookup_method = NULL;

	assert(opt);

	/*
	 * userspace probe fields are separated by ':'.
	 */
	tokens = strutils_split(opt, ':', 1);
	num_token = strutils_array_of_strings_len(tokens);

	/*
	 * Early sanity check that the number of parameter is between 2 and 4
	 * inclusively.
	 * elf:PATH:SYMBOL
	 * std:PATH:PROVIDER_NAME:PROBE_NAME
	 * PATH:SYMBOL (same behavior as ELF)
	 */
	if (num_token < 2 || num_token > 4) {
		ret = CMD_ERROR;
		goto end;
	}

	/*
	 * Looking up the first parameter will tell the technique to use to
	 * interpret the userspace probe/function description.
	 */
	switch (num_token) {
	case 2:
		/* When the probe type is omitted we assume ELF for now. */
	case 3:
		if (num_token == 3 && strcmp(tokens[0], "elf") == 0) {
			target_path = tokens[1];
			symbol_name = tokens[2];
		} else if (num_token == 2) {
			target_path = tokens[0];
			symbol_name = tokens[1];
		} else {
			ret = CMD_ERROR;
			goto end;
		}
		lookup_method =
			lttng_userspace_probe_location_lookup_method_function_elf_create();
		if (!lookup_method) {
			WARN("Failed to create ELF lookup method");
			ret = CMD_ERROR;
			goto end;
		}
		break;
	case 4:
		if (strcmp(tokens[0], "sdt") == 0) {
			target_path = tokens[1];
			provider_name = tokens[2];
			probe_name = tokens[3];
		} else {
			ret = CMD_ERROR;
			goto end;
		}
		lookup_method =
			lttng_userspace_probe_location_lookup_method_tracepoint_sdt_create();
		if (!lookup_method) {
			WARN("Failed to create SDT lookup method");
			ret = CMD_ERROR;
			goto end;
		}
		break;
	default:
		ret = CMD_ERROR;
		goto end;
	}

	/* strutils_unescape_string allocates a new char *. */
	unescaped_target_path = strutils_unescape_string(target_path, 0);
	if (!unescaped_target_path) {
		ret = CMD_ERROR;
		goto end;
	}

	/*
	 * If there is not forward slash in the path. Walk the $PATH else
	 * expand.
	 */
	if (strchr(unescaped_target_path, '/') == NULL) {
		/* Walk the $PATH variable to find the targeted binary. */
		real_target_path = zmalloc(LTTNG_PATH_MAX * sizeof(char));
		if (!real_target_path) {
			PERROR("Error allocating path buffer");
			ret = CMD_ERROR;
			goto end;
		}
		ret = walk_command_search_path(unescaped_target_path, real_target_path);
		if (ret) {
			ERR("Binary not found.");
			ret = CMD_ERROR;
			goto end;
		}
	} else {
		/*
		 * Expand references to `/./` and `/../`. This function does not check
		 * if the file exists. This call returns an allocated buffer on
		 * success.
		 */
		real_target_path = utils_expand_path_keep_symlink(unescaped_target_path);
		if (!real_target_path) {
			ERR("Error expanding the path to binary.");
			ret = CMD_ERROR;
			goto end;
		}

		/*
		 * Check if the file exists using access(2), If it does not,
		 * return an error.
		 */
		ret = access(real_target_path, F_OK);
		if (ret) {
			ERR("Cannot find binary at path: %s.", real_target_path);
			ret = CMD_ERROR;
			goto end;
		}
	}

	switch (lttng_userspace_probe_location_lookup_method_get_type(lookup_method)) {
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF:
		/*
		 * Check for common mistakes in userspace probe description syntax.
		 */
		ret = warn_userspace_probe_syntax(symbol_name);
		if (ret) {
			goto end;
		}

		probe_location_local = lttng_userspace_probe_location_function_create(
				real_target_path, symbol_name, lookup_method);
		if (!probe_location_local) {
			WARN("Failed to create function probe location");
			ret = CMD_ERROR;
			goto end;
		}

		/* Ownership transferred to probe_location. */
		lookup_method = NULL;
		break;
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT:
		probe_location_local = lttng_userspace_probe_location_tracepoint_create(
				real_target_path, provider_name, probe_name, lookup_method);
		if (!probe_location_local) {
			WARN("Failed to create function probe location");
			ret = CMD_ERROR;
			goto end;
		}

		/* Ownership transferred to probe_location. */
		lookup_method = NULL;
		break;
	default:
		ret = CMD_ERROR;
		goto end;
	}

	/*
	 * Everything went fine, transfer ownership of probe location to
	 * caller.
	 */
	*probe_location = probe_location_local;
	probe_location_local = NULL;

end:
	lttng_userspace_probe_location_destroy(probe_location_local);
	lttng_userspace_probe_location_lookup_method_destroy(lookup_method);
	strutils_free_null_terminated_array_of_strings(tokens);
	/*
	 * Freeing both char * here makes the error handling simplier. free()
	 * performs not action if the pointer is NULL.
	 */
	free(real_target_path);
	free(unescaped_target_path);

	return ret;
}
