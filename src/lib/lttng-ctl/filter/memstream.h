#ifndef _LTTNG_CTL_MEMSTREAM_H
#define _LTTNG_CTL_MEMSTREAM_H

/*
 * src/lib/lttng-ctl/memstream.h
 *
 * Copyright 2012 (c) - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * memstream compatibility layer.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 */

#ifdef LTTNG_HAVE_FMEMOPEN
#include <stdio.h>

static inline
FILE *lttng_fmemopen(void *buf, size_t size, const char *mode)
{
	return fmemopen(buf, size, mode);
}

#else /* LTTNG_HAVE_FMEMOPEN */

#include <stdlib.h>
#include <stdio.h>
#include <common/error.h>

/*
 * Fallback for systems which don't have fmemopen. Copy buffer to a
 * temporary file, and use that file as FILE * input.
 */
static inline
FILE *lttng_fmemopen(void *buf, size_t size, const char *mode)
{
	char tmpname[PATH_MAX];
	size_t len;
	FILE *fp;
	int ret;

	/*
	 * Support reading only.
	 */
	if (strcmp(mode, "rb") != 0) {
		return NULL;
	}
	strncpy(tmpname, "/tmp/lttng-tmp-XXXXXX", PATH_MAX);
	ret = mkstemp(tmpname);
	if (ret < 0) {
		return NULL;
	}
	/*
	 * We need to write to the file.
	 */
	fp = fdopen(ret, "w+");
	if (!fp) {
		goto error_unlink;
	}
	/* Copy the entire buffer to the file */
	len = fwrite(buf, sizeof(char), size, fp);
	if (len != size) {
		goto error_close;
	}
	ret = fseek(fp, 0L, SEEK_SET);
	if (ret < 0) {
		PERROR("fseek");
		goto error_close;
	}
	/* We keep the handle open, but can unlink the file on the VFS. */
	ret = unlink(tmpname);
	if (ret < 0) {
		PERROR("unlink");
	}
	return fp;

error_close:
	ret = fclose(fp);
	if (ret < 0) {
		PERROR("close");
	}
error_unlink:
	ret = unlink(tmpname);
	if (ret < 0) {
		PERROR("unlink");
	}
	return NULL;
}

#endif /* LTTNG_HAVE_FMEMOPEN */

#endif /* _LTTNG_CTL_MEMSTREAM_H */
