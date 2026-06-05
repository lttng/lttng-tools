/*
 * SPDX-FileCopyrightText: 2026 Philippe Proulx <philippe.proulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE

#include "export-maps-mi.hpp"

#include <common/error.hpp>
#include <common/format.hpp>
#include <common/mi-lttng.hpp>

#include <string>

namespace lttng {
namespace cli {
namespace export_maps {
namespace {

/*
 * RAII wrapper around the MI writer for the `export-maps` command: opens
 * the `<command>` element on construction and closes it on destruction.
 */
class mi_writer final {
public:
	mi_writer() : _mi_writer(mi_lttng_writer_create(fileno(stdout), LTTNG_MI_XML))
	{
		if (!_mi_writer) {
			LTTNG_THROW_ERROR("Failed to create MI writer");
		}

		if (mi_lttng_writer_command_open(_mi_writer.get(), "export-maps")) {
			LTTNG_THROW_ERROR("Failed to open MI `<command>` element");
		}
	}

	mi_writer(const mi_writer&) = delete;
	mi_writer(mi_writer&&) = delete;
	mi_writer& operator=(const mi_writer&) = delete;
	mi_writer& operator=(mi_writer&&) = delete;

	~mi_writer()
	{
		if (mi_lttng_writer_command_close(_mi_writer.get())) {
			ERR("Failed to close MI `<command>` element");
		}
	}

	void open_elem(const char *const name)
	{
		if (mi_lttng_writer_open_element(_mi_writer.get(), name)) {
			LTTNG_THROW_ERROR(fmt::format("Failed to open MI element `<{}>`", name));
		}
	}

	void close_elem()
	{
		if (mi_lttng_writer_close_element(_mi_writer.get())) {
			LTTNG_THROW_ERROR("Failed to close MI element");
		}
	}

	void write_output_elem(const std::string& sql)
	{
		if (mi_lttng_writer_write_element_string(
			    _mi_writer.get(), mi_lttng_element_command_output, sql.c_str())) {
			LTTNG_THROW_ERROR("Failed to write MI `<output>` element");
		}
	}

	void write_success_elem(const bool success)
	{
		if (mi_lttng_writer_write_element_bool(
			    _mi_writer.get(), mi_lttng_element_command_success, success ? 1 : 0)) {
			LTTNG_THROW_ERROR("Failed to write MI `<success>` element");
		}
	}

private:
	mi_writer_uptr _mi_writer;
};

} /* namespace */

void run_mi(const std::string& sql)
{
	mi_writer writer;

	try {
		writer.open_elem(mi_lttng_element_command_output);
		writer.open_elem("export-maps");
		writer.write_output_elem(sql);
		writer.close_elem();
		writer.close_elem();
	} catch (...) {
		writer.write_success_elem(false);
		throw;
	}

	writer.write_success_elem(true);
}

} /* namespace export_maps */
} /* namespace cli */
} /* namespace lttng */
