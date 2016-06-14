/*
 * Copyright (C) 2013 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LTTNG_SAVE_H
#define LTTNG_SAVE_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The lttng_save_session_attr object is opaque to the user. Use the helper
 * functions below to use them.
 */
struct lttng_save_session_attr;

/*
 * Return a newly allocated save session attribute object or NULL on error.
 */
struct lttng_save_session_attr *lttng_save_session_attr_create(void);

/*
 * Free a given save session attribute object.
 */
void lttng_save_session_attr_destroy(struct lttng_save_session_attr *output);


/*
 * Save session attribute getter family functions.
 */

/* Return session name. NULL indicated all sessions must be saved. */
const char *lttng_save_session_attr_get_session_name(
	struct lttng_save_session_attr *attr);
/*
 * Return destination URL. A NULL value indicates the default session
 * configuration location. The URL format used is documented in lttng(1).
 * NULL indicates that the default session configuration path is used.
 */
const char *lttng_save_session_attr_get_output_url(
	struct lttng_save_session_attr *attr);
/*
 * Return the configuration overwrite attribute. This attribute indicates
 * whether or not existing configuration files must be overwritten.
 */
int lttng_save_session_attr_get_overwrite(
	struct lttng_save_session_attr *attr);
/*
 * Return the omit name configuration attribute. This attribute indicates
 * whether or not the saved sessions' names should be omitted.
 */
int lttng_save_session_attr_get_omit_name(
	struct lttng_save_session_attr *attr);
/*
 * Return the omit output configuration attribute. This attribute indicates
 * whether or not the saved sessions' output configuration should be omitted.
 */
int lttng_save_session_attr_get_omit_output(
	struct lttng_save_session_attr *attr);

/*
 * Save session attribute setter family functions.
 *
 * For every set* call, 0 is returned on success or else -LTTNG_ERR_INVALID is
 * returned indicating that at least one given parameter is invalid.
 */

/*
 * Set the name of the session to save. A NULL name means all sessions
 * known to the session daemon will be saved.
 */
int lttng_save_session_attr_set_session_name(
	struct lttng_save_session_attr *attr, const char *session_name);
/*
 * Set the URL of the session configuration to save. A NULL value indicates the
 * use of the default location being the session one. The URL's format is is
 * documented in lttng(1).
 */
int lttng_save_session_attr_set_output_url(
	struct lttng_save_session_attr *attr, const char *url);
/*
 * Set the overwrite attribute. If set to true, files of the same name as the
 * current session configuration URL will be overwritten.
 */
int lttng_save_session_attr_set_overwrite(
	struct lttng_save_session_attr *attr, int overwrite);
/*
 * Set the omit name attribute. If set to true, the sessions' names are omitted
 * from the resulting session configuration file.
 */
int lttng_save_session_attr_set_omit_name(
	struct lttng_save_session_attr *attr, int omit_name);
/*
 * Set the omit output attribute. If set to true, the sessions' output
 * configurations are omitted from the resulting session configuration file.
 */
int lttng_save_session_attr_set_omit_output(
	struct lttng_save_session_attr *attr, int omit_output);

/*
 * Save session configuration(s).
 *
 * The lttng_save_session_attr object must not be NULL. No ownership of the
 * object is kept by the function; it must be released by the caller.
 *
 * Returns 0 on success or a negative LTTNG_ERR value on error.
 */
int lttng_save_session(struct lttng_save_session_attr *attr);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_SAVE_H */
