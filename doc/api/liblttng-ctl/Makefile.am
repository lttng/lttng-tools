# SPDX-License-Identifier: GPL-2.0-only

API_DOC_INSTALL_DIR = "$(DESTDIR)$(docdir)/api/liblttng-ctl"

all-local: doxygen-doc

install-data-local: doxygen-doc
	$(mkdir_p) "$(API_DOC_INSTALL_DIR)"
	cp -rv output/html "$(API_DOC_INSTALL_DIR)"

@DX_RULES@

headernames := \
	action/action.h \
	action/list.h \
	action/notify.h \
	action/path.h \
	action/rate-policy.h \
	action/rotate-session.h \
	action/snapshot-session.h \
	action/start-session.h \
	action/stop-session.h \
	channel.h \
	clear-handle.h \
	clear.h \
	condition/buffer-usage.h \
	condition/condition.h \
	condition/evaluation.h \
	condition/event-rule-matches.h \
	condition/session-consumed-size.h \
	condition/session-rotation.h \
	constant.h \
	destruction-handle.h \
	domain.h \
	endpoint.h \
	error-query.h \
	event-expr.h \
	event-field-value.h \
	event-rule/event-rule.h \
	event-rule/jul-logging.h \
	event-rule/kernel-kprobe.h \
	event-rule/kernel-syscall.h \
	event-rule/kernel-tracepoint.h \
	event-rule/kernel-uprobe.h \
	event-rule/log4j-logging.h \
	event-rule/log4j2-logging.h \
	event-rule/python-logging.h \
	event-rule/user-tracepoint.h \
	event.h \
	handle.h \
	health.h \
	kernel-probe.h \
	kernel.h \
	load.h \
	location.h \
	log-level-rule.h \
	lttng-error.h \
	lttng-export.h \
	lttng.h \
	notification/channel.h \
	notification/notification.h \
	rotation.h \
	save.h \
	session-descriptor.h \
	session.h \
	snapshot.h \
	tracker.h \
	trigger/trigger.h \
	userspace-probe.h

$(DX_DOCDIR)/$(PACKAGE).tag: \
	dox/groups.dox \
	Doxyfile \
	style.css \
	$(addprefix @top_srcdir@/include/lttng/,$(headernames))

MOSTLYCLEANFILES = $(DX_CLEANFILES)
EXTRA_DIST = \
	Doxyfile.in \
	style.css \
	dox \
	images
