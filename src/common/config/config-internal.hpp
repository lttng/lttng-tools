/*
 * SPDX-FileCopyrightText: 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <libxml/xmlwriter.h>
#include <stdio.h>

struct config_writer {
	xmlTextWriterPtr writer;
};
