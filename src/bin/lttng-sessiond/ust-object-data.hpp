/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_OBJECT_DATA_HPP
#define LTTNG_SESSIOND_UST_OBJECT_DATA_HPP

struct lttng_ust_abi_object_data;

namespace lttng {
namespace sessiond {
namespace ust {

/*
 * RAII wrapper for lttng_ust_abi_object_data pointers obtained from the
 * UST consumer daemon (channel objects, stream objects).
 *
 * The wrapped pointer is released via lttng_ust_ctl_release_object()
 * and freed on destruction. The socket fd is always -1 at release time
 * because the stream group outlives the applications: by the time the
 * stream group is destroyed, the app that created the buffers may have
 * already exited.
 */
class ust_object_data final {
public:
	/*
	 * Takes ownership of the raw pointer. The caller must not free
	 * or release the pointer after this call.
	 */
	explicit ust_object_data(lttng_ust_abi_object_data *data) noexcept;

	~ust_object_data();

	ust_object_data(ust_object_data&& other) noexcept;
	ust_object_data& operator=(ust_object_data&& other) noexcept;

	ust_object_data(const ust_object_data&) = delete;
	ust_object_data& operator=(const ust_object_data&) = delete;

	/*
	 * Create a duplicate of the wrapped object data via
	 * lttng_ust_ctl_duplicate_ust_object_data(). The duplicate is a
	 * new allocation with its own file descriptors.
	 *
	 * Used in per-UID mode to send copies of channel and stream
	 * objects to newly-registered applications that share the same
	 * UID+ABI.
	 *
	 * Throws on allocation or duplication failure.
	 */
	ust_object_data duplicate() const;

	lttng_ust_abi_object_data *get() const noexcept;

	/* Release ownership, returning the raw pointer. */
	lttng_ust_abi_object_data *release() noexcept;

private:
	void _cleanup() noexcept;

	lttng_ust_abi_object_data *_obj = nullptr;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_OBJECT_DATA_HPP */
