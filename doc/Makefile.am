# SPDX-FileCopyrightText: 2026 EfficiOS Inc.
#
# SPDX-License-Identifier: GPL-2.0-only

# The `examples` directory is left out since the parent Makefile is responsible
# of it. This is used to control when examples are built in the build process.
# Since some examples require the presence of liblttng-ctl and that the `src`
# objects might requires build artifacts from the `doc` directory, in build
# scenarios such as `--enable-embedded-help`, a forced build order is required
# at the parent level.
SUBDIRS = man

dist_doc_DATA =
	live-reading-howto.md \
	live-reading-protocol.md \
	python-howto.md \
	quickstart.md \
	relayd-architecture.md \
	snapshot-howto.md \
	streaming-howto.md \
	valgrind-howto.md

if API_DOC
SUBDIRS += api
endif
