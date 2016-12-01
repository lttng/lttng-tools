ACLOCAL_AMFLAGS = -I m4

DIST_SUBDIRS = include doc src extras tests

SUBDIRS = include doc src tests

if BUILD_EXTRAS
SUBDIRS += extras
endif

dist_doc_DATA = LICENSE \
                ChangeLog \
		README.md

dist_noinst_DATA = CodingStyle

EXTRA_DIST = extras/lttng-bash_completion gpl-2.0.txt lgpl-2.1.txt
