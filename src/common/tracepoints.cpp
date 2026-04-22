/*
 * SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "tracepoints.hpp"

#include <common/compat/getenv.hpp>
#include <common/defaults.hpp>
#include <common/format.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/make-unique.hpp>

#include <dlfcn.h>
#include <string>
#include <sys/stat.h>
#include <unordered_set>

namespace {
std::vector<std::string> split_paths(const std::string& paths)
{
	std::vector<std::string> result;
	std::string::size_type current = 0;

	while (current < paths.size()) {
		const auto next = paths.find(':', current);
		auto entry = paths.substr(current, next - current);

		if (!entry.empty()) {
			result.push_back(std::move(entry));
		}

		if (next == std::string::npos) {
			break;
		}

		current = next + 1;
	}

	return result;
}

std::vector<std::string> get_tp_search_paths()
{
	/*
	 * 1. LTTNG_TP_PATH
	 * 2. LD_LIBRARY_PATH (+ /lttng)
	 * 3. LTTNG_LIB_DIR (libdir/lttng)
	 */
	std::vector<std::string> paths;
	std::unordered_set<std::string> seen;

	const auto push_back_unique = [&paths, &seen](std::string element) {
		if (seen.find(element) == seen.end()) {
			seen.insert(element);
			paths.push_back(std::move(element));
		}
	};

	const char *tp_paths_env = lttng_secure_getenv(DEFAULT_TRACEPOINT_PROVIDER_PATH_ENV);
	if (tp_paths_env != nullptr) {
		for (auto&& path : split_paths(std::string(tp_paths_env))) {
			push_back_unique(std::move(path));
		}
	}

	const char *loader_library_path = lttng_secure_getenv("LD_LIBRARY_PATH");
	if (loader_library_path != nullptr) {
		for (const auto& path : split_paths(std::string(loader_library_path))) {
			push_back_unique(path + "/lttng");
		}
	}

	push_back_unique(LTTNG_LIB_DIR);
	return paths;
}

std::vector<std::string> tracepoints_find_all(const std::string& basename)
{
	auto search_paths = get_tp_search_paths();
	std::vector<std::string> options;

	if (search_paths.empty()) {
		return options;
	}

	for (const auto& path : search_paths) {
		DBG_FMT("Checking for tracepoint library='{}', path='{}'", basename, path);
		struct stat statbuf = {};
		auto file = fmt::format("{}/{}", path, basename);
		if (stat(file.c_str(), &statbuf) != 0) {
			DBG_FMT("Stat '{}' failed: {} ({})", file, strerror(errno), errno);
		} else if (statbuf.st_mode & S_IFREG) {
			options.push_back(std::move(file));
		} else {
			DBG_FMT("'{}' is not a file or symbolic link, skipping", file);
		}
	}

	return options;
}
} /* namespace */

namespace lttng {
namespace tracepoints {
namespace details {
void tracepoints_unload(void *tracepoint)
{
	if (tracepoint == nullptr) {
		return;
	}

	if (dlclose(tracepoint)) {
		WARN_FMT("Failed to `dlclose` tracepoints provider {}: {}", tracepoint, dlerror());
	} else {
		DBG_FMT("Called `dlclose` on tracepoints provider {}", tracepoint);
	}
}
} /* namespace details */
} /* namespace tracepoints */
} /* namespace lttng */

std::unique_ptr<void,
		lttng::memory::create_deleter_class<
			void,
			lttng::tracepoints::details::tracepoints_unload>::deleter>
tracepoints_load(const char *basename)
{
	auto options = ::tracepoints_find_all(std::string(basename));
	void *ret = nullptr;
	for (const auto& path : options) {
		dlerror();
		ret = dlopen(path.c_str(), RTLD_NOW);
		if (ret != nullptr) {
			DBG_FMT("Loaded tracepoints provider at '{}': {}", path, ret);
			break;
		}
		DBG_FMT("Failed to load shared object '{}': {}", path, dlerror());
	}

	if (ret == nullptr) {
		WARN_FMT("Failed to load tracepoint provider '{}': {}", basename, dlerror());
	}

	return lttng::make_unique_wrapper<void, lttng::tracepoints::details::tracepoints_unload>(
		ret);
}
