LTTng-tools man pages
=====================

This directory contains the sources of the LTTng-tools man pages.

LTTng-tools man pages are written in
[AsciiDoc](http://www.methods.co.nz/asciidoc/), and then converted to
DocBook (XML) using the `asciidoc` command, and finally to troff using
the appropriate DocBook XSL stylesheet (using the `xmlto` command).


Custom XSL stylesheets
----------------------

There are a few custom XSL stylesheets applied for customizing the
generated man pages in the `xsl` directory.


Macros
------

AsciiDoc is configured with `asciidoc.conf` which contains a few
macro definitions used everywhere in the man page sources.


### man

The man macro is used to link to another man page. In troff, the man
page name is rendered in bold.

Usage example: `man:lttng-enable-channel(1)`.


### linkgenoptions

The linkgenoptions macro is used to link to the general options
section of the `lttng(1)` command.

Usage example: `See the linkgenoptions:(general options).`.


### option

The option macro is used to write a command-line option which is
defined in the same man page.

Usage example: `option:--no-output`, `option:--loglevel=TRACE_WARNING`


### nloption

Command-line option generating no link. This is used when talking
about a generic option which is defined in many man pages.

Usage example: `nloption:--jul`


### genoption

General (`lttng(1)`) command-line option, for generating the appropriate
cross-man-page link.

Usage example: `genoption:--group`, `genoption:--sessiond-path`


### not

The `:not:` macro is used to emphasize on _not_.


### escwc

The `:escwc:` macro is used to output `\*` literally in the man page,
which is not so easy to do otherwise.


Includes
--------

  * `common-cmd-footer.txt`: common `lttng` command footer.
  * `common-cmd-help-options.txt`: common program information section
    of `lttng` command options.
  * `common-cmd-options-head.txt`: common `lttng` command head of
    options section.
  * `common-footer.txt`: common footer for all commands.


Convention
----------

Please follow those rules when updating the current man pages or
writing new ones:

  * Always use macros when possible (link to other LTTng man page,
    command-line option, NOT, etc.).
  * Use callouts with the `term` role for command-line examples.
  * Always refer to _long_ options in the text.
  * Use the `option:--option=parameter` format (with `=`) when providing
    a parameter to long options.
  * Write _user space_, not _userspace_ nor _user-space_.
    (neither _user land_).
  * Write _file system_, not _filesystem_.
  * Write _use case_, not _use-case_ nor _usecase_.
  * Write _log level_, not _loglevel_.
  * Write complete LTTng project names: _LTTng-modules_, _LTTng-UST_ and
    _LTTng-tools_, not _modules_, _UST_ and _tools_.
  * Prefer simple emphasis to strong emphasis for emphasizing text.
  * Try to stay behind the 72th column mark if possible, and behind
    the 80th column otherwise.
  * Do not end directory paths with a forward slash
    (good: `include/trace/events`, bad: `include/trace/events/`).
  * Minimize the use of the future tense (_will_).
  * Do not use Latin abbreviations (_e.g._, _i.e._, _etc._).
