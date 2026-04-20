/*
 * SPDX-FileCopyrightText: 2026 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef LTTNG_VERSION_GIT_HPP
#define LTTNG_VERSION_GIT_HPP

namespace lttng {

/*
 * Return the "git describe --tags --dirty" string captured at build time,
 * or an empty string if this isn't a git checkout or the build is an
 * exact-tag clean build.
 *
 * This function is defined in its own translation unit (version-git.cpp)
 * which is the only one including the volatile "version-git.i" header.
 * Keeping it separate from the stable EXTRA_VERSION_* macros in
 * "version.hpp" avoids rebuilding every caller when the working tree flips
 * between clean and dirty.
 */
const char *get_git_version() noexcept;

} /* namespace lttng */

#endif /* LTTNG_VERSION_GIT_HPP */
