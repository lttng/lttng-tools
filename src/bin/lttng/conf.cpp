/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "conf.hpp"

#include <common/common.hpp>
#include <common/compat/errno.hpp>
#include <common/format.hpp>
#include <common/utils.hpp>

#include <fstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace {

std::string get_config_file_path(const char *path)
{
	return lttng::format("{}/{}", path, CONFIG_FILENAME);
}

/*
 * Look for a "session=<name>" entry in the config file at `path`.
 * Returns the session name on success, or an empty string if not found.
 */
std::string read_session_name_from_config(const char *path)
{
	const auto file_path = get_config_file_path(path);
	std::ifstream config_file(file_path);

	if (!config_file.is_open()) {
		return {};
	}

	std::string line;
	while (std::getline(config_file, line)) {
		const auto eq_pos = line.find('=');

		if (eq_pos == std::string::npos) {
			continue;
		}

		const auto key = line.substr(0, eq_pos);
		const auto value = line.substr(eq_pos + 1);

		if (key == "session" && !value.empty()) {
			return value;
		}
	}

	return {};
}

} /* namespace */

/*
 * Creates the empty config file at the path.
 * On success, returns 0;
 * on error, returns -1.
 */
static int create_config_file(const char *path)
{
	const auto file_path = get_config_file_path(path);

	std::ofstream config_file(file_path);
	if (!config_file.is_open()) {
		PWARN("Failed to open configuration file '%s'", file_path.c_str());
		return -1;
	}

	return 0;
}

/*
 * Append data to the config file at file_path.
 * On success, returns 0;
 * on error, returns -1.
 */
static int write_config(const char *file_path, const std::string& data)
{
	const auto full_path = get_config_file_path(file_path);

	std::ofstream config_file(full_path, std::ios::app);
	if (!config_file.is_open()) {
		PWARN("Failed to open configuration file '%s'", full_path.c_str());
		return -1;
	}

	config_file << data;
	if (!config_file.good()) {
		return -1;
	}

	return 0;
}

void config_destroy(const char *path)
{
	try {
		const auto config_path = get_config_file_path(path);

		if (!config_exists(config_path.c_str())) {
			return;
		}

		DBG("Removing %s\n", config_path.c_str());
		const auto ret = remove(config_path.c_str());
		if (ret < 0) {
			PERROR("remove config file");
		}
	} catch (const std::exception& ex) {
		ERR_FMT("Failed to destroy configuration file: {}", ex.what());
	}
}

void config_destroy_default()
{
	const char *path = utils_get_home_dir();
	if (path == nullptr) {
		return;
	}
	config_destroy(path);
}

int config_exists(const char *path)
{
	struct stat info;

	const auto ret = stat(path, &info);
	if (ret < 0) {
		return 0;
	}
	return S_ISREG(info.st_mode) || S_ISDIR(info.st_mode);
}

char *config_read_session_name(const char *path)
{
	try {
		const auto session_name = read_session_name_from_config(path);

		if (session_name.empty()) {
			const char *home_dir = utils_get_home_dir();

			ERR("Can't find valid lttng config %s/.lttngrc", home_dir);
			MSG("Did you create a session? (lttng create <my_session>)");
			return nullptr;
		}

		return strdup(session_name.c_str());
	} catch (const std::exception& ex) {
		ERR_FMT("Failed to read session name from configuration file: {}", ex.what());
		return nullptr;
	}
}

char *config_read_session_name_quiet(const char *path)
{
	try {
		const auto session_name = read_session_name_from_config(path);

		if (session_name.empty()) {
			return nullptr;
		}

		return strdup(session_name.c_str());
	} catch (const std::exception& ex) {
		ERR_FMT("Failed to read session name from configuration file: {}", ex.what());
		return nullptr;
	}
}

int config_add_session_name(const char *path, const char *name)
{
	try {
		return write_config(path, lttng::format("session={}", name));
	} catch (const std::exception& ex) {
		ERR_FMT("Failed to add session name to configuration file: {}", ex.what());
		return -1;
	}
}

int config_init(const char *session_name)
{
	const char *path = utils_get_home_dir();
	if (path == nullptr) {
		return -1;
	}

	try {
		auto ret = create_config_file(path);
		if (ret < 0) {
			return ret;
		}

		ret = config_add_session_name(path, session_name);
		if (ret < 0) {
			return ret;
		}

		DBG("Init config session in %s", path);
		return 0;
	} catch (const std::exception& ex) {
		ERR_FMT("Failed to initialize configuration: {}", ex.what());
		return -1;
	}
}
