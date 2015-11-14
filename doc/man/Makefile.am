# Man pages are only built if the --enable-build-man-pages option was passed
# to the configure script.
#
# They should always be built before creating a distribution tarball.

# function which adds the source directory prefix and adds a given suffix
manaddsuffix = $(addsuffix $(1),$(addprefix $(srcdir)/,$(2)))

# List only the names without the .*.txt extension here:
MAN1_NAMES = \
	lttng \
	lttng-create \
	lttng-destroy \
	lttng-set-session \
	lttng-save \
	lttng-load \
	lttng-start \
	lttng-stop \
	lttng-version \
	lttng-view \
	lttng-enable-channel \
	lttng-disable-channel \
	lttng-add-context \
	lttng-list \
	lttng-calibrate \
	lttng-track \
	lttng-untrack \
	lttng-status \
	lttng-help
MAN3_NAMES =
MAN8_NAMES =
MAN1_NO_ASCIIDOC_NAMES = lttng-crash
MAN3_NO_ASCIIDOC_NAMES =
MAN8_NO_ASCIIDOC_NAMES = lttng-relayd lttng-sessiond

# man pages destinations
MAN1 = $(call manaddsuffix,.1,$(MAN1_NAMES))
MAN3 = $(call manaddsuffix,.3,$(MAN3_NAMES))
MAN8 = $(call manaddsuffix,.8,$(MAN8_NAMES))
MAN1_NO_ASCIIDOC = $(call manaddsuffix,.1,$(MAN1_NO_ASCIIDOC_NAMES))
MAN3_NO_ASCIIDOC = $(call manaddsuffix,.3,$(MAN3_NO_ASCIIDOC_NAMES))
MAN8_NO_ASCIIDOC = $(call manaddsuffix,.8,$(MAN8_NO_ASCIIDOC_NAMES))
MAN = $(MAN1) $(MAN3) $(MAN8)

# those are always installed since they are written in troff
dist_man1_MANS = $(MAN1_NO_ASCIIDOC)
dist_man3_MANS = $(MAN3_NO_ASCIIDOC)
dist_man8_MANS = $(MAN8_NO_ASCIIDOC)

# only build man pages if it was enabled
if BUILD_MAN_PAGES
# dist + install
dist_man1_MANS += $(MAN1)
dist_man3_MANS += $(MAN3)
dist_man8_MANS += $(MAN8)

# AsciiDoc sources and outputs
MAN1_TXT = $(call manaddsuffix,.1.txt,$(MAN1_NAMES))
MAN3_TXT = $(call manaddsuffix,.3.txt,$(MAN3_NAMES))
MAN8_TXT = $(call manaddsuffix,.8.txt,$(MAN8_NAMES))
MAN_TXT = $(MAN1_TXT) $(MAN3_TXT) $(MAN8_TXT)
MAN_XML = $(patsubst $(srcdir)/%.txt,%.xml,$(MAN_TXT))

# common AsciiDoc source files
COMMON_TXT = \
	$(srcdir)/common-footer.txt \
	$(srcdir)/common-cmd-footer.txt \
	$(srcdir)/common-cmd-options-head.txt \
	$(srcdir)/common-cmd-help-options.txt

# config
ASCIIDOC_CONF = $(srcdir)/asciidoc.conf
XSL_FILES = \
	manpage.xsl \
	manpage-base.xsl \
	manpage-bold-literal.xsl \
	manpage-ulinks.xsl
XSL_SRC_FILES = $(addprefix $(srcdir)/xsl/,$(XSL_FILES))

# common dependencies
COMMON_DEPS = $(ASCIIDOC_CONF) $(COMMON_TXT)

# tools
ADOC = $(ASCIIDOC) -f $(ASCIIDOC_CONF) -d manpage \
	-a lttng_version=$(PACKAGE_VERSION)
ADOC_DOCBOOK = $(ADOC) -b docbook
XTO = $(XMLTO) -m $(firstword $(XSL_SRC_FILES)) man

# recipes
%.1.xml: $(srcdir)/%.1.txt $(COMMON_DEPS)
	$(ADOC_DOCBOOK) -o $@ $<

%.1: %.1.xml $(XSL_SRC_FILES)
	$(XTO) $<

%.3.xml: $(srcdir)/%.3.txt $(COMMON_DEPS)
	$(ADOC_DOCBOOK) -o $@ $<

%.3: %.3.xml $(XSL_SRC_FILES)
	$(XTO) $<

%.8.xml: $(srcdir)/%.8.txt $(COMMON_DEPS)
	$(ADOC_DOCBOOK) -o $@ $<

%.8: %.8.xml $(XSL_SRC_FILES)
	$(XTO) $<

clean-local:
	rm -rf $(MAN_XML)
	rm -rf $(MAN)
else
if IN_GIT_REPO
# we are in the Git repo: the man pages should be built for distribution
dist-hook:
	@echo
	@echo 'Error: Please build the man pages before creating a tarball.'
	@echo
	@false
else
# we are in the tarball, hence the man pages are already built
dist_man1_MANS += $(MAN1)
dist_man3_MANS += $(MAN3)
dist_man8_MANS += $(MAN8)
endif # IN_GIT_REPO
endif # BUILD_MAN_PAGES
