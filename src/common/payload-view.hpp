/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_PAYLOAD_VIEW_H
#define LTTNG_PAYLOAD_VIEW_H

#include <common/buffer-view.hpp>
#include <common/dynamic-array.hpp>

struct lttng_payload;
struct fd_handle;

/*
 * An lttng_payload_view references a payload and allows code to share
 * a `const` version of a subset of a payload.
 *
 * A payload view is invalidated whenever its source (a payload, or another
 * payload view) is modified.
 *
 * While a payload view does not allow users to modify the underlying bytes
 * of the payload, it can be used to 'pop' file descriptor handles using an
 * iterator belonging to the top-level payload view.
 *
 * Hence, a payload view created from a	payload or a dynamic buffer contains
 * an implicit file descriptor handle iterator. Any payload view created from
 * another payload view will share the same underlying file descriptor handle
 * iterator.
 *
 * The rationale for this is that a payload is never consumed directly, it must
 * be consumed through a payload view.
 *
 * Typically, a payload view will be used to rebuild a previously serialized
 * object hierarchy. Sharing an underlying iterator allows aggregate objects
 * to provide a restricted view of the payload to their members, which will
 * report the number of bytes consumed and `pop` the file descriptor handle they
 * should own. In return, those objects can create an even narrower view for
 * their children, allowing them to also consume file descriptor handles.
 *
 * Note that a payload view never assumes any ownership of the underlying
 * payload.
 */
struct lttng_payload_view {
	struct lttng_buffer_view buffer;
	/* private */

	const struct lttng_dynamic_pointer_array _fd_handles;

	struct {
		size_t *p_fd_handles_position;
		size_t fd_handles_position;
	} _iterator;
};

/**
 * Checks if a payload view's buffer is safe to access.
 *
 * After calling the payload view creation functions, callers should verify
 * if the resquested length (if any is explicitly provided) could be mapped
 * to a new view.
 *
 * @view	Payload to validate
 */
bool lttng_payload_view_is_valid(const struct lttng_payload_view *view);

/**
 * Return a payload view referencing a subset of a payload.
 *
 * @payload	Source payload to reference
 * @offset	Offset to apply to the payload's buffer
 * @len		Length of the contents to reference. Passing -1 will
 *		cause the view to reference the whole payload from the
 *		offset provided.
 */
struct lttng_payload_view
lttng_payload_view_from_payload(const struct lttng_payload *payload, size_t offset, ptrdiff_t len);

/**
 * Return a payload view referencing a subset of a payload referenced by
 * another payload view.
 *
 * @view	Source payload view to reference
 * @offset	Offset to apply to the payload view's buffer view
 * @len		Length of the contents to reference. Passing -1 will
 *		cause the payload view to reference the whole payload view's
 *		buffer view from the offset provided.
 */
struct lttng_payload_view
lttng_payload_view_from_view(struct lttng_payload_view *view, size_t offset, ptrdiff_t len);

/**
 * Return a payload view referencing a subset of a dynamic buffer.
 *
 * Meant as an adapter for code paths that need to create a payload view
 * from an existing dynamic buffer.
 *
 * @src		Source dynamic buffer to reference
 * @offset	Offset to apply to the dynamic buffer
 * @len		Length of the buffer contents to reference. Passing -1 will
 *		cause the payload view to reference the whole payload from the
 *		offset provided.
 */
struct lttng_payload_view lttng_payload_view_from_dynamic_buffer(
	const struct lttng_dynamic_buffer *buffer, size_t offset, ptrdiff_t len);
/**
 *
 * Return a payload view referencing a subset of a dynamic buffer.
 *
 * Meant as an adapter for code paths that need to create a payload view
 * from an existing buffer view.
 *
 * @src		Source buffer view to reference
 * @offset	Offset to apply to the buffer view
 * @len		Length of the buffer contents to reference. Passing -1 will
 *		cause the payload view to reference the whole payload from the
 *		offset provided.
 */
struct lttng_payload_view lttng_payload_view_from_buffer_view(const struct lttng_buffer_view *view,
							      size_t offset,
							      ptrdiff_t len);

/**
 * Return a payload view referencing a subset of the memory referenced by a raw
 * pointer.
 *
 * @src		Source buffer to reference
 * @offset	Offset to apply to the source memory buffer
 * @len		Length of the memory contents to reference.
 *
 * Note that a payload view never assumes the ownership of the memory it
 * references.
 */
struct lttng_payload_view
lttng_payload_view_init_from_buffer(const char *src, size_t offset, ptrdiff_t len);

/**
 * Get the number of file descriptor handles left in a payload view.
 *
 * @payload	Payload instance
 *
 * Returns the number of file descriptor handles left on success, -1 on error.
 */
int lttng_payload_view_get_fd_handle_count(const struct lttng_payload_view *payload_view);

/**
 * Pop an fd handle from a payload view.
 *
 * A reference to the returned fd_handle is acquired on behalf of the caller.
 *
 * @payload	Payload instance
 *
 * Returns an fd_handle on success, -1 on error.
 */
struct fd_handle *lttng_payload_view_pop_fd_handle(struct lttng_payload_view *payload_view);

#endif /* LTTNG_PAYLOAD_VIEW_H */
