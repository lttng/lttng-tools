/*
 * SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONFIG_TRIGGER_CONFIG_H
#define LTTNG_CONFIG_TRIGGER_CONFIG_H

#include <libxml/tree.h>

/*
 * Accumulates the triggers parsed from one or more session configuration
 * files so that they can be registered once every session has been loaded.
 *
 * Opaque to the session configuration loader.
 */
struct trigger_load_state;

/*
 * Create a trigger load state.
 *
 * Returns a newly allocated state on success or NULL on error.
 */
struct trigger_load_state *trigger_load_state_create(void);

/*
 * Destroy a trigger load state.
 */
void trigger_load_state_destroy(struct trigger_load_state *state);

/*
 * Parse the `<triggers>` XML node `triggers_node`, deserialize each contained
 * `<trigger>`, and for each one:
 *
 *   - If a trigger with the same name already exists in the session daemon
 *     and its condition or action differs, fail (a negative LTTNG_ERR code is
 *     returned): the caller must abort the whole load without creating any
 *     session or trigger.
 *   - If a trigger with the same name already exists and is identical (same
 *     condition and action), skip it.
 *   - Otherwise, record it to be registered later (deduplicated by name
 *     across successive calls).
 *
 * This function does not register anything: it only parses and validates so
 * that a same-name conflict can abort the load before any session is created.
 *
 * Returns 0 on success or a negative LTTNG_ERR code on error.
 */
int trigger_load_state_process_node(struct trigger_load_state *state, xmlNodePtr triggers_node);

/*
 * Register every trigger recorded by trigger_load_state_process_node().
 *
 * Call once all the sessions have been loaded, because some trigger actions
 * (for example "increment map value") target channels of the loaded
 * sessions, which must therefore exist first.
 *
 * Returns 0 on success or a negative LTTNG_ERR code on error.
 */
int trigger_load_state_register(struct trigger_load_state *state);

#endif /* LTTNG_CONFIG_TRIGGER_CONFIG_H */
