LTTng-tools man pages
=====================

This directory contains the sources of the LTTng-tools man pages.

LTTng-tools man pages are written in AsciiDoc, and then converted to
DocBook (XML) using the `asciidoc` command, and finally to troff
using the appropriate DocBook XSL stylesheet (using the `xmlto`
command). AsciiDoc sources can also be converted to HTML5 directly by
the `asciidoc` command.


Make targets
------------

The default Make target builds the troff man pages.

The `html` target builds the HTML man pages.


Custom XSL stylesheets
----------------------

There are a few custom XSL stylesheets applied for generating the man
pages in the `xsl` directory:


Macros
------

AsciiDoc is configured with `asciidoc.conf` which contains a few
macro definitions used everywhere in the man page sources.


### `linklttng`

The `linklttng` macro is used to link to another LTTng man page. Its
output is different depending on the back-end. In troff, the man page
name is rendered in bold, whereas the HTML5 output renders a hyperlink.

Usage example: `linklttng:lttng-enable-channel(1)`.


### `option`

The `option` macro is used to write a command-line option.

Usage example: `option:--no-output`.


Includes
--------

Include `common-footer.txt` after the `OPTIONS` section.

Include `common-help-options.txt` at the end of the `OPTIONS`
section of a command's man page. This should be followed by a
custom `SEE ALSO` section for each command.


Convention
----------

Please follow the following rules when updating the current man pages
or writing new ones:

  * Always use macros when possible (link to other LTTng man page,
    command-line option).
  * Use callouts for command-line examples.
  * Always refer to _long_ options in the text.
  * Use the `option:--option=parameter` format (with `=`) when providing
    a parameter to long options.
  * Use _user space_, not _userspace_ nor _user-space_.
    (neither _user land_).
  * Use _file system_, not _filesystem_.
  * Use _use case_, not _use-case_ nor _usecase_.
  * Use _log level_, not _loglevel_.
  * Use complete LTTng project names: _LTTng-modules_, _LTTng-UST_ and
    _LTTng-tools_, not _modules_, _UST_ and _tools_.
  * Prefer simple emphasis to strong emphasis for emphasizing text.
  * Try to stay behind the 72th column mark if possible, and behind
    the 80th column otherwise.
  * Do not end directory paths with a forward slash
    (good: `include/trace/events`, bad: `include/trace/events/`).
  * Keep the text as impersonal as possible (minimize the use of
    _I_, _we_, _us_, _you_, etc.).
  * Minimize the use of the future tense (_will_).
  * Do not use Latin abbreviations (_e.g._, _i.e._, _etc._).
