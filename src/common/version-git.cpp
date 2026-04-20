/*
 * SPDX-FileCopyrightText: 2026 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <version-git.hpp>
#include <version-git.i>

const char *lttng::get_git_version() noexcept
{
	return GIT_VERSION;
}
