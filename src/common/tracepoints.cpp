/*
 * SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "tracepoints.hpp"

#include <common/compat/getenv.hpp>
#include <common/defaults.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/make-unique.hpp>

#include <dlfcn.h>
#include <string>
#include <sys/stat.h>

namespace {
std::vector<std::string> split_paths(const std::string& paths)
{
	std::vector<std::string> result;
	std::string::size_type current = 0;

	while (current < paths.size()) {
		const auto next = paths.find(':', current);
		auto entry = paths.substr(current, next - current);

		if (!entry.empty()) {
			result.push_back(entry);
		}

		if (next == std::string::npos) {
			break;
		}

		current = next + 1;
	}

	return result;
}

void push_back_unique(std::vector<std::string>& v, std::string element)
{
	bool add = true;
	for (auto e : v) {
		if (e.compare(element) == 0) {
			add = false;
			break;
		}
	}

	if (add) {
		v.push_back(std::move(element));
	}
}

std::vector<std::string> _search_paths()
{
	/*
	 * 1. LTTNG_TP_PATH
	 * 2. LD_LIBRARY_PATH (+ /lttng)
	 * 3. LTTNG_LIB_DIR (libdir/lttng)
	 */
	std::vector<std::string> paths;
	const char *_tp_paths = lttng_secure_getenv(DEFAULT_TRACEPOINT_PROVIDER_PATH_ENV);
	if (_tp_paths != nullptr) {
		for (auto path : split_paths(std::string(_tp_paths))) {
			push_back_unique(paths, path);
		}
	}

	const char *_ld_library_path = lttng_secure_getenv("LD_LIBRARY_PATH");
	if (_ld_library_path != nullptr) {
		for (auto path : split_paths(std::string(_ld_library_path))) {
			push_back_unique(paths, path + "/lttng");
		}
	}

	push_back_unique(paths, std::string(LTTNG_LIB_DIR));
	return paths;
}

std::vector<std::string> tracepoints_find_all(const std::string& basename)
{
	auto search_paths = ::_search_paths();
	std::vector<std::string> options;

	if (search_paths.empty()) {
		return options;
	}

	for (auto path : search_paths) {
		DBG_FMT("Checking for tracepoint library='{}', path='{}'", basename, path);
		struct stat statbuf = {};
		auto file = path + "/" + basename;
		if (stat(file.c_str(), &statbuf) != 0) {
			DBG_FMT("Stat '{}' failed: {} ({})", file, strerror(errno), errno);
		} else if (statbuf.st_mode & S_IFREG) {
			options.push_back(file);
		} else {
			DBG_FMT("'{}' is not a file or symbolic link, skipping", file);
		}
	}

	return options;
}
} // namespace

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
	for (auto path : options) {
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
