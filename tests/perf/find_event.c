/*
 * Copyright (C) 2016 Julien Desfossez <jdesfossez@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <stdio.h>
#include <perfmon/pfmlib.h>
#include <string.h>

int main(int argc, char **argv)
{
	int ret, i;
	unsigned int j;
	pfm_pmu_info_t pinfo;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <pmu counter to find>\n"
				"ex: %s UNHALTED_REFERENCE_CYCLES\n"
				"Returns the first occurence it finds with "
				"return code 0.\n"
				"If not found returns 1, on error returns -1\n",
				argv[0], argv[0]);
		ret = -1;
		goto end;
	}

	memset(&pinfo, 0, sizeof(pinfo));
	pinfo.size = sizeof(pinfo);

	ret = pfm_initialize();
	if (ret != PFM_SUCCESS) {
		fprintf(stderr, "Failed to initialise libpfm: %s",
				pfm_strerror(ret));
		ret = -1;
		goto end;
	}

	pfm_for_all_pmus(j) {
		ret = pfm_get_pmu_info(j, &pinfo);
		if (ret != PFM_SUCCESS) {
			continue;
		}

		for (i = pinfo.first_event; i != -1; i = pfm_get_event_next(i)) {
			pfm_event_info_t info =
					{ .size = sizeof(pfm_event_info_t) };

			ret = pfm_get_event_info(i, PFM_OS_NONE, &info);
			if (ret != PFM_SUCCESS) {
				fprintf(stderr, "Cannot get event info: %s\n",
						pfm_strerror(ret));
				ret = -1;
				goto end;
			}

			if (info.pmu != j) {
				continue;
			}

			if (strcmp(info.name, argv[1]) == 0) {
				fprintf(stdout, "r%" PRIx64 "\n", info.code);
				ret = 0;
				goto end;
			}
		}
	}

	ret = 1;

end:
	return ret;
}
