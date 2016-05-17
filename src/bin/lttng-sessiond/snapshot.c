/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
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

#define _LGPL_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include <urcu/uatomic.h>

#include <common/defaults.h>

#include "snapshot.h"
#include "utils.h"

/*
 * Return the atomically incremented value of next_output_id.
 */
static inline unsigned long get_next_output_id(struct snapshot *snapshot)
{
	return uatomic_add_return(&snapshot->next_output_id, 1);
}

/*
 * Initialized snapshot output with the given values.
 *
 * Return 0 on success or else a negative value.
 */
static int output_init(uint64_t max_size, const char *name,
		struct lttng_uri *uris, size_t nb_uri,
		struct consumer_output *consumer, struct snapshot_output *output,
		struct snapshot *snapshot)
{
	int ret = 0, i;

	memset(output, 0, sizeof(struct snapshot_output));

	/*
	 * max_size of -1ULL means unset. Set to default (unlimited).
	 */
	if (max_size == (uint64_t) -1ULL) {
		max_size = 0;
	}
	output->max_size = max_size;

	if (snapshot) {
		output->id = get_next_output_id(snapshot);
	}
	lttng_ht_node_init_ulong(&output->node, (unsigned long) output->id);

	if (name && name[0] != '\0') {
		if (lttng_strncpy(output->name, name, sizeof(output->name))) {
			ret = -LTTNG_ERR_INVALID;
			goto error;
		}
	} else {
		/* Set default name. */
		ret = snprintf(output->name, sizeof(output->name), "%s-%" PRIu32,
				DEFAULT_SNAPSHOT_NAME, output->id);
		if (ret < 0) {
			ret = -ENOMEM;
			goto error;
		}
	}

	if (!consumer) {
		goto end;
	}

	output->consumer = consumer_copy_output(consumer);
	if (!output->consumer) {
		ret = -ENOMEM;
		goto error;
	}
	output->consumer->snapshot = 1;

	/* No URL given. */
	if (nb_uri == 0) {
		ret = 0;
		goto end;
	}

	if (uris[0].dtype == LTTNG_DST_PATH) {
		memset(output->consumer->dst.trace_path, 0,
				sizeof(output->consumer->dst.trace_path));
		if (lttng_strncpy(output->consumer->dst.trace_path,
				uris[0].dst.path,
				sizeof(output->consumer->dst.trace_path))) {
			ret = -LTTNG_ERR_INVALID;
			goto error;
		}
		output->consumer->type = CONSUMER_DST_LOCAL;
		ret = 0;
		goto end;
	}

	if (nb_uri != 2) {
		/* Absolutely needs two URIs for network. */
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	for (i = 0; i < nb_uri; i ++) {
		/* Network URIs */
		ret = consumer_set_network_uri(output->consumer, &uris[i]);
		if (ret < 0) {
			goto error;
		}
	}

error:
end:
	return ret;
}

/*
 * Initialize a snapshot output object using the given parameters and URI(s).
 * The name value and uris can be NULL.
 *
 * Return 0 on success or else a negative value.
 */
int snapshot_output_init_with_uri(uint64_t max_size, const char *name,
		struct lttng_uri *uris, size_t nb_uri,
		struct consumer_output *consumer, struct snapshot_output *output,
		struct snapshot *snapshot)
{
	return output_init(max_size, name, uris, nb_uri, consumer, output,
			snapshot);
}

/*
 * Initialize a snapshot output object using the given parameters. The name
 * value and url can be NULL.
 *
 * Return 0 on success or else a negative value.
 */
int snapshot_output_init(uint64_t max_size, const char *name,
		const char *ctrl_url, const char *data_url,
		struct consumer_output *consumer, struct snapshot_output *output,
		struct snapshot *snapshot)
{
	int ret = 0, nb_uri;
	struct lttng_uri *uris = NULL;

	/* Create an array of URIs from URLs. */
	nb_uri = uri_parse_str_urls(ctrl_url, data_url, &uris);
	if (nb_uri < 0) {
		ret = nb_uri;
		goto error;
	}

	ret = output_init(max_size, name, uris, nb_uri, consumer, output,
			snapshot);

error:
	free(uris);
	return ret;
}

struct snapshot_output *snapshot_output_alloc(void)
{
	return zmalloc(sizeof(struct snapshot_output));
}

/*
 * Delete output from the snapshot object.
 */
void snapshot_delete_output(struct snapshot *snapshot,
		struct snapshot_output *output)
{
	int ret;
	struct lttng_ht_iter iter;

	assert(snapshot);
	assert(snapshot->output_ht);
	assert(output);

	iter.iter.node = &output->node.node;
	rcu_read_lock();
	ret = lttng_ht_del(snapshot->output_ht, &iter);
	rcu_read_unlock();
	assert(!ret);
	/*
	 * This is safe because the ownership of a snapshot object is in a session
	 * for which the session lock need to be acquired to read and modify it.
	 */
	snapshot->nb_output--;
}

/*
 * Add output object to the snapshot.
 */
void snapshot_add_output(struct snapshot *snapshot,
		struct snapshot_output *output)
{
	assert(snapshot);
	assert(snapshot->output_ht);
	assert(output);

	rcu_read_lock();
	lttng_ht_add_unique_ulong(snapshot->output_ht, &output->node);
	rcu_read_unlock();
	/*
	 * This is safe because the ownership of a snapshot object is in a session
	 * for which the session lock need to be acquired to read and modify it.
	 */
	snapshot->nb_output++;
}

/*
 * Destroy and free a snapshot output object.
 */
void snapshot_output_destroy(struct snapshot_output *obj)
{
	assert(obj);

	if (obj->consumer) {
		consumer_output_send_destroy_relayd(obj->consumer);
		consumer_output_put(obj->consumer);
	}
	free(obj);
}

/*
 * RCU read side lock MUST be acquired before calling this since the returned
 * pointer is in a RCU hash table.
 *
 * Return the reference on success or else NULL.
 */
struct snapshot_output *snapshot_find_output_by_name(const char *name,
		struct snapshot *snapshot)
{
	struct lttng_ht_iter iter;
	struct snapshot_output *output = NULL;

	assert(snapshot);
	assert(name);

	cds_lfht_for_each_entry(snapshot->output_ht->ht, &iter.iter, output,
		node.node) {
		if (!strncmp(output->name, name, strlen(name))) {
			return output;
		}
	}

	/* Not found */
	return NULL;
}

/*
 * RCU read side lock MUST be acquired before calling this since the returned
 * pointer is in a RCU hash table.
 *
 * Return the reference on success or else NULL.
 */
struct snapshot_output *snapshot_find_output_by_id(uint32_t id,
		struct snapshot *snapshot)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;
	struct snapshot_output *output = NULL;

	assert(snapshot);

	lttng_ht_lookup(snapshot->output_ht, (void *)((unsigned long) id), &iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (!node) {
		DBG3("Snapshot output not found with id %" PRId32, id);
		goto error;
	}
	output = caa_container_of(node, struct snapshot_output, node);

error:
	return output;
}

/*
 * Initialized a snapshot object that was already allocated.
 *
 * Return 0 on success or else a negative errno value.
 */
int snapshot_init(struct snapshot *obj)
{
	int ret;

	assert(obj);

	memset(obj, 0, sizeof(struct snapshot));

	obj->output_ht = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	if (!obj->output_ht) {
		ret = -ENOMEM;
		goto error;
	}

	ret = 0;

error:
	return ret;
}

/*
 * Destroy snapshot object but the pointer is not freed so it's safe to pass a
 * static reference.
 */
void snapshot_destroy(struct snapshot *obj)
{
	struct lttng_ht_iter iter;
	struct snapshot_output *output;

	assert(obj);

	rcu_read_lock();
	cds_lfht_for_each_entry(obj->output_ht->ht, &iter.iter, output,
			node.node) {
		snapshot_delete_output(obj, output);
		snapshot_output_destroy(output);
	}
	rcu_read_unlock();
	ht_cleanup_push(obj->output_ht);
}
