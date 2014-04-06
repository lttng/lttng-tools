/*
 * Copyright (C) 2014 - Jonathan Rajotte <jonathan.r.julien@gmail.com>
 *                    - Olivier Cotte <olivier.cotte@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <include/config.h>
#include <common/config/config.h>

#include "mi-lttng.h"

/* Strings related to command */
const char * const mi_lttng_element_command = "command";
const char * const mi_lttng_element_command_version = "version";
const char * const mi_lttng_element_command_list = "list";
const char * const mi_lttng_element_command_name = "name";
const char * const mi_lttng_element_command_output = "output";

/* Strings related to command: version */
const char * const mi_lttng_element_version = "version";
const char * const mi_lttng_element_version_str = "string";
const char * const mi_lttng_element_version_web = "url";
const char * const mi_lttng_element_version_major = "major";
const char * const mi_lttng_element_version_minor = "minor";
const char * const mi_lttng_element_version_license = "license";
const char * const mi_lttng_element_version_patch_level = "patchLevel";
const char * const mi_lttng_element_version_description = "description";

LTTNG_HIDDEN
struct mi_writer *mi_lttng_writer_create(int fd_output, int mi_output_type)
{
	struct mi_writer *mi_writer;

	mi_writer = zmalloc(sizeof(struct mi_writer));
	if (!mi_writer) {
		PERROR("zmalloc mi_writer_create");
		goto end;
	}
	if (mi_output_type == LTTNG_MI_XML) {
		mi_writer->writer = config_writer_create(fd_output);
		if (!mi_writer->writer) {
			goto err_destroy;
		}
		mi_writer->type = LTTNG_MI_XML;
	} else {
		goto err_destroy;
	}

end:
	return mi_writer;

err_destroy:
	free(mi_writer);
	return NULL;
}

LTTNG_HIDDEN
int mi_lttng_writer_destroy(struct mi_writer *writer)
{
	int ret;

	if (!writer) {
		ret = -EINVAL;
		goto end;
	}

	ret = config_writer_destroy(writer->writer);
	if (ret < 0) {
		goto end;
	}

	free(writer);
end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_writer_command_open(struct mi_writer *writer, const char *command)
{
	int ret;

	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_command);
	if (ret) {
		goto end;
	}
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_command_name, command);
end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_writer_command_close(struct mi_writer *writer)
{
	return mi_lttng_writer_close_element(writer);
}

LTTNG_HIDDEN
int mi_lttng_writer_open_element(struct mi_writer *writer,
		const char *element_name)
{
	return config_writer_open_element(writer->writer, element_name);
}

LTTNG_HIDDEN
int mi_lttng_writer_close_element(struct mi_writer *writer)
{
	return config_writer_close_element(writer->writer);
}

LTTNG_HIDDEN
int mi_lttng_writer_write_element_unsigned_int(struct mi_writer *writer,
		const char *element_name, uint64_t value)
{
	return config_writer_write_element_unsigned_int(writer->writer,
			element_name, value);
}

LTTNG_HIDDEN
int mi_lttng_writer_write_element_signed_int(struct mi_writer *writer,
		const char *element_name, int64_t value)
{
	return config_writer_write_element_signed_int(writer->writer,
			element_name, value);
}

LTTNG_HIDDEN
int mi_lttng_writer_write_element_bool(struct mi_writer *writer,
		const char *element_name, int value)
{
	return config_writer_write_element_bool(writer->writer,
			element_name, value);
}

LTTNG_HIDDEN
int mi_lttng_writer_write_element_string(struct mi_writer *writer,
		const char *element_name, const char *value)
{
	return config_writer_write_element_string(writer->writer,
			element_name, value);
}

LTTNG_HIDDEN
int mi_lttng_version(struct mi_writer *writer, struct mi_lttng_version *version,
	const char *lttng_description, const char *lttng_license)
{
	int ret;

	/* Open version */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_version);
	if (ret) {
		goto end;
	}

	/* Version string (contain info like rc etc.) */
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_version_str, VERSION);
	if (ret) {
		goto end;
	}

	/* Major version number */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			mi_lttng_element_version_major, version->version_major);
	if (ret) {
		goto end;
	}

	/* Minor version number */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			mi_lttng_element_version_minor, version->version_minor);
	if (ret) {
		goto end;
	}

	/* Patch number */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			mi_lttng_element_version_patch_level, version->version_patchlevel);
	if (ret) {
		goto end;
	}

	/* Name of the version */
	ret = mi_lttng_writer_write_element_string(writer,
			config_element_name, version->version_name);
	if (ret) {
		goto end;
	}

	/* Description mostly related to beer... */
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_version_description, lttng_description);
	if (ret) {
		goto end;
	}

	/* url */
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_version_web, version->package_url);
	if (ret) {
		goto end;
	}

	/* License: free as in free beer...no...*speech* */
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_version_license, lttng_license);
	if (ret) {
		goto end;
	}

	/* Close version element */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}

LTTNG_HIDDEN
int mi_lttng_session(struct mi_writer *writer,
		struct lttng_session *session, int is_open)
{
	int ret;

	/* open sessions element */
	ret = mi_lttng_writer_open_element(writer,
			config_element_session);
	if (ret) {
		goto end;
	}

	/* Name of the session */
	ret = mi_lttng_writer_write_element_string(writer,
			config_element_name, session->name);
	if (ret) {
		goto end;
	}

	/* path */
	ret = mi_lttng_writer_write_element_string(writer,
			config_element_path, session->path);
	if (ret) {
		goto end;
	}

	/* enabled ? */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			config_element_enabled, session->enabled);
	if (ret) {
		goto end;
	}

	/* snapshot mode */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			config_element_snapshot_mode, session->snapshot_mode);
	if (ret) {
		goto end;
	}

	/* live timer interval in usec */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			config_element_live_timer_interval,
			session->live_timer_interval);
	if (ret) {
		goto end;
	}

	if (!is_open) {
		/* Closing session element */
		ret = mi_lttng_writer_close_element(writer);
	}
end:
	return ret;

}
