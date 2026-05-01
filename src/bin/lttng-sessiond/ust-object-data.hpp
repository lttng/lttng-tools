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

struct app;

/*
 * RAII wrapper for lttng_ust_abi_object_data pointers.
 *
 * Used both for objects whose lifetime extends beyond the application
 * that produced them (per-UID stream/map groups) and for per-app
 * objects (channel, stream, event, context, event-notifier handles).
 *
 * The destructor only performs local cleanup
 * (`lttng_ust_ctl_release_object(-1, ...)`) and frees the storage.
 *
 * When the tracer must additionally be notified to release its handle, the
 * owning code calls `release_object_via_app()` (or
 * `protocol_guard::release_object()`) before the wrapper is destroyed.
 *
 * Because `lttng_ust_ctl_release_object()` zeroes the per-type local state on
 * each call, the wrapper's subsequent local-cleanup pass is safe.
 */
class ust_object_data final {
public:
	/* Empty wrapper (`get()` returns `nullptr`). */
	ust_object_data() noexcept = default;

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

	/*
	 * Close any local file descriptors and free any local buffers held by the
	 * wrapped object.
	 *
	 * After this call, the local cleanup is done; a later release issued through
	 * a real socket will only send the release notification to the tracer.
	 *
	 * This is meant to be used once an object has been sent to an application.
	 * Every descriptor the object carried has been duplicated into the
	 * application's process at send time, so the session daemon's copy is
	 * usually redundant. That is not always true, however; whether it is safe to
	 * release locally as soon as the send succeeds (rather than wait for the
	 * wrapping structure to be destroyed) depends on what the object is:
	 *
	 *   Channels
	 *     A channel object carries two things: a wakeup descriptor (the write
	 *     end of a pipe whose read end the consumer daemon holds) and a small
	 *     data blob describing the channel's layout, such as subbuffer size,
	 *     count, transport, and so on.
	 *
	 *     The data blob is safe to free early. The wakeup descriptor is not.
	 *
	 *     For channels the pipe's role is to signal "liveliness". The consumer
	 *     daemon polls its read end and watches for the moment every writer has
	 *     closed its end. That hangup is the cue to start destroying the channel
	 *     on its side.
	 *
	 *     The consumer daemon has already let go of its own write end by the
	 *     time the session daemon receives the channel: the consumer created
	 *     the pipe, kept the read end, sent the write end up the stack, and
	 *     closed its local copy. So the session daemon's copy is the only
	 *     writer that does not go away when traced applications exit.
	 *     Releasing it early lets the pipe lose its last writer as soon as the
	 *     last application dies, racing any later flush, stop, or destroy
	 *     command keyed on that channel.
	 *
	 *     The wakeup descriptor therefore has to stay open until the
	 *     per-application channel object is destroyed, where its close and the
	 *     release notification to the tracer happen together.
	 *
	 *   Streams
	 *     A stream object carries two descriptors. The first is a shared-memory
	 *     descriptor backing the stream's ring buffer: the application writes
	 *     trace records into it and the consumer daemon reads them out. The
	 *     second is a wakeup descriptor, the write end of a per-stream pipe
	 *     that the application writes a byte on to nudge the consumer when
	 *     fresh packets are available.
	 *
	 *     Both are safe to drop early on the per-application reference this
	 *     method is called on.
	 *
	 *     The consumer daemon holds both ends of every stream pipe for the
	 *     stream's whole lifetime and is the one that drives stream teardown.
	 *
	 *     The session daemon's handle on a stream takes one of two shapes. In
	 *     per-pid mode, the only session-daemon-side reference is the
	 *     per-application stream object. In per-uid mode, a long-lived master
	 *     stream held by the recording session is duplicated into a fresh
	 *     per-application stream object for every newly registered
	 *     application.
	 *
	 *     Either way, the object this method touches at the call site is the
	 *     per-application one. Dropping its descriptors after a successful
	 *     send leaves the consumer's writers, the application's own copy, and
	 *     (in per-uid) the master untouched.
	 *
	 *   Counters
	 *     The master counter handle carries no descriptor at all, only a small
	 *     configuration blob describing the counter's dimensions. The per-CPU
	 *     and per-channel counter handles each carry one shared-memory
	 *     descriptor backing the counter's storage, mapped by both the
	 *     application and the consumer daemon.
	 *
	 *   Events, contexts, event notifiers, event notifier groups, and counter
	 *   events
	 *     These objects have no per-type local cleanup. They carry no
	 *     descriptors and no local buffers, so this method is a no-op for them.
	 */
	void release_local_fds() noexcept;

private:
	void _cleanup() noexcept;

	lttng_ust_abi_object_data *_obj = nullptr;
};

/*
 * Notify the application's tracer to release `obj` via the app's
 * command socket and log any failure with `kind` as context (e.g.
 * "channel", "event", "context"). Safe to call on a wrapper whose local
 * cleanup has already been performed: only the tracer-side notification
 * is sent in that case.
 *
 * Used by per-app `ust_object_data` owners just before the wrapper is
 * destroyed. The wrapper's own destructor then performs its
 * local-cleanup pass, which is a no-op once this function has run
 * because `lttng_ust_ctl_release_object()` zeroes the relevant fields.
 */
void release_object_via_app(app& app, lttng_ust_abi_object_data& obj, const char *kind) noexcept;

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_OBJECT_DATA_HPP */
