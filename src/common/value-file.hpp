/*
 * SPDX-FileCopyrightText: 2024 Kienan Stewart <kstewart@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_COMMON_VALUE_FILE_HPP
#define LTTNG_COMMON_VALUE_FILE_HPP

#include <common/error.hpp>
#include <common/format.hpp>
#include <common/string-utils/c-string-view.hpp>

#include <exception>
#include <fstream>
#include <stdio.h>
#include <string.h>
#include <string>

/*
 * Write a value to the given path and filename.
 *
 * Returns 0 on success and -1 on failure.
 */
template <typename ValueType>
int utils_create_value_file(const ValueType value, const lttng::c_string_view filepath)
{
	DBG_FMT("Creating value file: path=`{}`, value={}", filepath, value);
	try {
		std::ofstream file;
		const auto tmp_filepath = std::string(filepath.data()) + ".tmp";

		file.exceptions(std::ofstream::failbit | std::ofstream::badbit);
		/* Open the temporary file with truncation to create or overwrite it. */
		file.open(tmp_filepath, std::ios::out | std::ios::trunc);
		file << value << std::endl;
		file.close();

		/* Rename the temporary file to the final filepath. */
		if (rename(tmp_filepath.c_str(), filepath.data()) != 0) {
			ERR_FMT("Failed to rename temporary file: temp_path=`{}`, final_path=`{}`, error=`{}`",
				tmp_filepath,
				filepath,
				strerror(errno));
			return -1;
		}
	} catch (const std::exception& e) {
		ERR_FMT("Failed to produce value file: path=`{}`, value={}, error=`{}`",
			filepath,
			value,
			e.what());
		return -1;
	}

	return 0;
}

#endif /* LTTNG_COMMON_VALUE_FILE_HPP */
