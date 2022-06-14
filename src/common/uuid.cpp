/*
 * Copyright (C) 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright (C) 2019 Michael Jeanson <mjeanson@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/compat/string.hpp>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "uuid.hpp"

namespace {
const lttng_uuid nil_uuid = {};
bool lttng_uuid_is_init;
} /* namespace */

void lttng_uuid_to_str(const lttng_uuid& uuid, char *uuid_str)
{
	sprintf(uuid_str, LTTNG_UUID_FMT, LTTNG_UUID_FMT_VALUES(uuid));
}

std::string lttng::utils::uuid_to_str(const lttng_uuid& uuid)
{
	std::string uuid_str(LTTNG_UUID_STR_LEN, '\0');

	::lttng_uuid_to_str(uuid, &uuid_str[0]);

	/* Don't include '\0' in the C++ string. */
	uuid_str.resize(uuid_str.size() - 1);

	return uuid_str;
}

int lttng_uuid_from_str(const char *str_in, lttng_uuid& uuid_out)
{
	int ret = 0;
	lttng_uuid uuid_scan;

	if (str_in == nullptr) {
		ret = -1;
		goto end;
	}

	if (lttng_strnlen(str_in, LTTNG_UUID_STR_LEN) != LTTNG_UUID_STR_LEN - 1) {
		ret = -1;
		goto end;
	}

	/* Scan to a temporary location in case of a partial match. */
	if (sscanf(str_in, LTTNG_UUID_FMT, LTTNG_UUID_SCAN_VALUES(uuid_scan)) !=
			LTTNG_UUID_LEN) {
		ret = -1;
		goto end;
	}

	uuid_out = uuid_scan;
end:
	return ret;
}

bool lttng_uuid_is_nil(const lttng_uuid& uuid)
{
	return uuid == nil_uuid;
}

/*
 * Generate a random UUID according to RFC4122, section 4.4.
 */
int lttng_uuid_generate(lttng_uuid& uuid_out)
{
	int i, ret = 0;

	if (!lttng_uuid_is_init) {
		/*
		 * We don't need cryptographic quality randomness to
		 * generate UUIDs, seed rand with the epoch.
		 */
		const time_t epoch = time(NULL);

		if (epoch == (time_t) -1) {
			ret = -1;
			goto end;
		}

		srand(epoch);
		lttng_uuid_is_init = true;
	}

	/*
	 * Generate 16 bytes of random bits.
	 */
	for (i = 0; i < LTTNG_UUID_LEN; i++) {
		uuid_out[i] = (uint8_t) rand();
	}

	/*
	 * Set the two most significant bits (bits 6 and 7) of the
	 * clock_seq_hi_and_reserved to zero and one, respectively.
	 */
	uuid_out[8] &= ~(1 << 6);
	uuid_out[8] |= (1 << 7);

	/*
	 * Set the four most significant bits (bits 12 through 15) of the
	 * time_hi_and_version field to the 4-bit version number from
	 * Section 4.1.3.
	 */
	uuid_out[6] &= 0x0f;
	uuid_out[6] |= (LTTNG_UUID_VER << 4);

end:
	return ret;
}
