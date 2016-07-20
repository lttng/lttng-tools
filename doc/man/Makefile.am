# Man pages are only built if they are enabled at configure time.
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
	lttng-help \
	lttng-snapshot \
	lttng-enable-event \
	lttng-disable-event \
	lttng-crash \
	lttng-metadata \
	lttng-regenerate
MAN3_NAMES =
MAN8_NAMES = lttng-sessiond lttng-relayd
MAN1_NO_ASCIIDOC_NAMES =
MAN3_NO_ASCIIDOC_NAMES = lttng-health-check
MAN8_NO_ASCIIDOC_NAMES =

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
ASCIIDOC_ATTRS_CONF = $(builddir)/asciidoc-attrs.conf
XSL_FILES = \
	manpage.xsl \
	manpage-callouts.xsl \
	manpage-bold-literal.xsl \
	manpage-links.xsl
XSL_SRC_FILES = $(addprefix $(srcdir)/xsl/,$(XSL_FILES))

# common dependencies
COMMON_DEPS = $(ASCIIDOC_CONF) $(COMMON_TXT) $(ASCIIDOC_ATTRS_CONF)

# man pages destinations
MAN1 = $(addsuffix .1,$(MAN1_NAMES))
MAN3 = $(addsuffix .3,$(MAN3_NAMES))
MAN8 = $(addsuffix .8,$(MAN8_NAMES))
MAN1_NO_ASCIIDOC = $(addsuffix .1,$(MAN1_NO_ASCIIDOC_NAMES))
MAN3_NO_ASCIIDOC = $(addsuffix .3,$(MAN3_NO_ASCIIDOC_NAMES))
MAN8_NO_ASCIIDOC = $(addsuffix .8,$(MAN8_NO_ASCIIDOC_NAMES))
MAN = $(MAN1) $(MAN3) $(MAN8)

if MAN_PAGES_OPT
# at this point, we know the user asked to build the man pages
if HAVE_ASCIIDOC_XMLTO
# tools
ADOC = $(ASCIIDOC) -f $(ASCIIDOC_CONF) -f $(ASCIIDOC_ATTRS_CONF) -d manpage
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

# only clean the generated files if we have the tools to generate them again
CLEANFILES = $(MAN_XML) $(MAN)
else # HAVE_ASCIIDOC_XMLTO
# create man page targets used to stop the build if we want to
# build the man pages, but we don't have the necessary tools to do so
ERR_MSG = "Error: Cannot build target because asciidoc or xmlto tool is missing."
ERR_MSG += "Make sure both tools are installed and run the configure script again."

%.1: $(srcdir)/%.1.txt $(COMMON_DEPS)
	@echo $(ERR_MSG)
	@false

%.3: $(srcdir)/%.3.txt $(COMMON_DEPS)
	@echo $(ERR_MSG)
	@false

%.8: $(srcdir)/%.8.txt $(COMMON_DEPS)
	@echo $(ERR_MSG)
	@false
endif # HAVE_ASCIIDOC_XMLTO
endif # MAN_PAGES_OPT

# those are always installed since they are directly written in troff
dist_man1_MANS = $(MAN1_NO_ASCIIDOC)
dist_man3_MANS = $(MAN3_NO_ASCIIDOC)
dist_man8_MANS = $(MAN8_NO_ASCIIDOC)

if MAN_PAGES_OPT
# building man pages: we can install and distribute them
dist_man1_MANS += $(MAN1)
dist_man3_MANS += $(MAN3)
dist_man8_MANS += $(MAN8)
endif # MAN_PAGES_OPT

if !MAN_PAGES_OPT
dist-hook:
	@echo "Error: Please enable the man pages before creating a distribution tarball."
	@false
endif # !MAN_PAGES_OPT

# always distribute the source files
EXTRA_DIST = $(MAN_TXT) $(COMMON_TXT) $(XSL_SRC_FILES) \
	$(ASCIIDOC_CONF) $(ASCIIDOC_ATTRS_CONF).in
