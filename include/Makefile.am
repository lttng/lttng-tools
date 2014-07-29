##
## The version.h file must be verified and generated or updated if the
## git commit id (called git version here) changed since the last build
## of lttng-tools.
##
version.h:
	##
	## We first create variables for the current git version and
	## the locations of the version.h and version.h.tmpl files
	##
	@echo -n "Generating version.h ... "
	@(version_h_tmpl="$(top_srcdir)/include/version.h.tmpl"; \
	if [ -f "$${version_h_tmpl}" ]; then \
		version_h="$(top_builddir)/include/version.h"; \
		##
		## We check the git version format we will use depending on
		## whether or not we are in the master branch or on a tag
		##
		git_branch="$$(git describe --all 2>/dev/null)"; \
		if [ -z "$${git_branch}" ]; then \
			git_version=""; \
		else \
			git_describe="$$(git describe)"; \
			if [ "$${git_branch}" == "$${git_describe}" ]; then \
				git_version="$${git_describe}"; \
			else \
				git_version="$$(git describe --long --all)"; \
			fi; \
		fi; \
		##
		## If the version.h file doesn't exist or is not up to date,
		## We replace it by the version.h.tmpl file
		##
		if [ ! -e "$${version_h}" ] || \
			[ "$${version_h_tmpl}" -nt "$${version_h}" ]; then \
			cp "$${version_h_tmpl}" "$${version_h}"; \
		fi; \
		if [ -n "$${git_version}" ]; then \
			##
			## We remove the leading "v" for the version number
			##
			git_version="$$(echo "$${git_version}" | sed -r "s/^v([0-9])/\1/")"; \
			##
			## If we have a git version, we verify that it isn't the same
			## as the one currently in the file (if there is one), as we
			## don't want to update the file if it is already up to date
			##
			if [ $$(grep -cE "^#define GIT_VERSION_SED \"?$${git_version}\"?$$" "$${version_h}") -eq 0 ]; then \
				sed -i "s'^#define GIT_VERSION_SED.*$$'#define GIT_VERSION \"$${git_version}\"'" "$${version_h}"; \
			fi; \
		fi; \
	fi)
	@echo "ok"

##
## version.h is defined as a .PHONY file even if it's a real file as
## we want our routine to be runned for each build.
##
.PHONY: version.h

lttnginclude_HEADERS = \
	lttng/health.h \
	lttng/lttng.h \
	lttng/constant.h \
	lttng/channel.h \
	lttng/domain.h \
	lttng/event.h \
	lttng/handle.h \
	lttng/session.h \
	lttng/lttng-error.h \
	lttng/snapshot.h \
	lttng/save.h \
	lttng/load.h \
	version.h

noinst_HEADERS = \
	lttng/snapshot-internal.h \
	lttng/health-internal.h \
	lttng/save-internal.h \
	lttng/load-internal.h
