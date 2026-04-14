/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_APP_SESSION_HPP
#define LTTNG_SESSIOND_UST_APP_SESSION_HPP

#include "ust-app-objd-registry.hpp"
#include "ust-app-session-id.hpp"

#include <common/credentials.hpp>
#include <common/macros.hpp>

#include <lttng/domain.h>

#include <memory>
#include <stdint.h>
#include <string>
#include <unordered_map>

struct consumer_output;
struct ust_app_channel;

namespace lttng {
namespace sessiond {
namespace ust {
class domain_orchestrator;
class trace_class;
struct app;
} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

namespace lttng {
namespace sessiond {
namespace ust {

class app_session {
public:
	using identifier = app_session_identifier;

	/*
	 * Construct an app session. The consumer_output pointer must
	 * already have had its reference count incremented by the
	 * caller; the app_session does not acquire an additional
	 * reference.
	 */
	explicit app_session(ust::app& app,
			     std::uint64_t recording_session_id,
			     std::uint64_t app_session_id,
			     lttng_credentials real_credentials,
			     lttng_credentials effective_credentials,
			     lttng_buffer_type buffer_type,
			     std::uint32_t bits_per_long,
			     std::string path,
			     std::string root_shm_path,
			     std::string shm_path,
			     consumer_output *consumer);

	~app_session();

	app_session(const app_session&) = delete;
	app_session(app_session&&) = delete;
	app_session& operator=(const app_session&) = delete;
	app_session& operator=(app_session&&) = delete;

	ust::app& app() noexcept
	{
		return _app;
	}

	const ust::app& app() const noexcept
	{
		return _app;
	}

	identifier get_identifier() const noexcept
	{
		LTTNG_ASSERT(bits_per_long == 32 || bits_per_long == 64);
		LTTNG_ASSERT(buffer_type == LTTNG_BUFFER_PER_PID ||
			     buffer_type == LTTNG_BUFFER_PER_UID);

		return { .app_session_id = app_session_id,
			 .recording_session_id = recording_session_id,
			 .app_credentials = real_credentials,
			 .abi = bits_per_long == 32 ? identifier::application_abi::ABI_32 :
						      identifier::application_abi::ABI_64,
			 .allocation_policy = buffer_type == LTTNG_BUFFER_PER_PID ?
				 identifier::buffer_allocation_policy::PER_PID :
				 identifier::buffer_allocation_policy::PER_UID };
	}

	static std::shared_ptr<ust::trace_class> get_registry(const identifier& identifier);

	static std::uint64_t next_id();

	int flush();

	bool enabled = false;
	/* started: has the session been in started state at any time ? */
	bool started = false; /* allows detection of start vs restart. */
	int handle = -1; /* used as unique identifier for app session */

	bool deleted = false; /* Session deleted flag. */

	/*
	 * Recording session ID (ltt_session::id). Multiple app_sessions
	 * can share the same recording_session_id since each application
	 * gets its own app_session for the same recording session.
	 */
	const std::uint64_t recording_session_id;
	/* Unique app_session identifier, allocated by sessiond. */
	const std::uint64_t app_session_id;
	/* Per-app channels indexed by channel name. */
	std::unordered_map<std::string, std::unique_ptr<ust_app_channel>> channels;

	/*
	 * RAII token: registers this session's UST tracer-side handle
	 * in the owning app's objd_registry. Deregisters automatically
	 * when this app_session is destroyed.
	 *
	 * Optional because the token is acquired after the UST handle
	 * is created (not at construction time).
	 */
	nonstd::optional<app_objd_registry::registration_token> objd_token;
	/* Starts with 'ust'; no leading slash. */
	const std::string path;
	/* UID/GID of the application owning the session */
	const lttng_credentials real_credentials;
	/* Effective UID and GID. Same as the tracing session. */
	const lttng_credentials effective_credentials;
	/*
	 * Once at least *one* session is created onto the application, the
	 * corresponding consumer is set so we can use it on unregistration.
	 */
	::consumer_output *consumer;
	const enum lttng_buffer_type buffer_type;
	/* ABI of the session. Same value as the application. */
	const std::uint32_t bits_per_long;

	const std::string root_shm_path;
	const std::string shm_path;

private:
	static int close_metadata(uint64_t metadata_key,
				  unsigned int consumer_bitness,
				  struct consumer_output *consumer);

	ust::app& _app;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#ifdef HAVE_LIBLTTNG_UST_CTL

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* LTTNG_SESSIOND_UST_APP_SESSION_HPP */
