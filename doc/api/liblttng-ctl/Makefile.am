# SPDX-License-Identifier: GPL-2.0-only

API_DOC_INSTALL_DIR = "$(DESTDIR)$(docdir)/api/liblttng-ctl"

all-local: doxygen-doc

install-data-local: doxygen-doc
	$(mkdir_p) "$(API_DOC_INSTALL_DIR)"
	cp -rv output/html "$(API_DOC_INSTALL_DIR)"

@DX_RULES@

MOSTLYCLEANFILES = $(DX_CLEANFILES)
EXTRA_DIST = \
	Doxyfile.in \
	DoxygenLayout.xml \
	style.css \
	dox \
	images
