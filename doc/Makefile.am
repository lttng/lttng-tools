# SPDX-License-Identifier: GPL-2.0-only

# The `examples` directory is left out since the parent Makefile is responsible
# of it. This is used to control when examples are built in the build process.
# Since some examples require the presence of liblttng-ctl and that the `src`
# objects might requires build artifacts from the `doc` directory, in build
# scenarios such as `--enable-embedded-help`, a forced build order is required
# at the parent level.
SUBDIRS = man
EXTRA_DIST = quickstart.txt streaming-howto.txt python-howto.txt \
	snapshot-howto.txt kernel-CodingStyle.txt \
	live-reading-howto.txt live-reading-protocol.txt \
	relayd-architecture.txt

dist_doc_DATA = quickstart.txt streaming-howto.txt python-howto.txt \
	snapshot-howto.txt live-reading-howto.txt \
	live-reading-protocol.txt valgrind-howto.txt

if API_DOC
SUBDIRS += api
endif
