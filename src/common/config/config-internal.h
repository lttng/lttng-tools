/*
 * Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <libxml/xmlwriter.h>
#include <stdio.h>

struct config_writer {
	xmlTextWriterPtr writer;
};
