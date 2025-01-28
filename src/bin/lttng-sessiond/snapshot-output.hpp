/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_SNAPSHOT_OUTPUT_HPP
#define LTTNG_SNAPSHOT_OUTPUT_HPP

int snapshot_output_init(const ltt_session::locked_ref& session,
			 uint64_t max_size,
			 const char *name,
			 const char *ctrl_url,
			 const char *data_url,
			 struct consumer_output *consumer,
			 struct snapshot_output *output,
			 struct snapshot *snapshot);
int snapshot_output_init_with_uri(const ltt_session::locked_ref& session,
				  uint64_t max_size,
				  const char *name,
				  struct lttng_uri *uris,
				  size_t nb_uri,
				  struct consumer_output *consumer,
				  struct snapshot_output *output,
				  struct snapshot *snapshot);

#endif /* LTTNG_SNAPSHOT_OUTPUT_HPP */
