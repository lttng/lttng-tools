# LTTng-tools contributor's guide

Being an open source project, the LTTng-tools project welcomes
contributions from anyone. This guide walks you through the process
of contributing a patch to LTTng-tools.


## Getting the source code

The LTTng-tools project uses [Git](https://git-scm.com/) for version
control. The upstream Git repository URL is:

    https://git.lttng.org/lttng-tools.git


## Coding standard

See [CodingStyle](./CodingStyle.md) or style and design guidelines.

See the [tests README](./tests/README.adoc) for test-related guidelines.

## Creating and sending a patch

LTTng-tools's development flow is primarily based on
[Gerrit Code Review](https://review.lttng.org), although we also accept
e-mail based patch series on the
[`lttng-dev` mailing list](https://lists.lttng.org/cgi-bin/mailman/listinfo/lttng-dev)
and pull requests on our [GitHub mirror](https://github.com/lttng/lttng-tools).
If you're going to create GitHub pull requests, make sure you still follow the
guidelines below.

The mailing list is also used to share and comment on
<abbr title="Request for Comments">RFC</abbr>s and answer
user questions.

A template commit message is available below, and as a file that you may
configure your local check out to use:

    git config commit.template .commit_template

A pre-commit hook may also be installed that will use various tools to lint
stylistic errors before the commit is complete. This hook requires the following
development tools:

  * clang-tidy
  * clang-format
  * python-black
  * python-clang

The pre-commit hook may be installed with the following command:

    ln -s ../../extras/pre-commit.py .git/hooks/pre-commit

Once your changes have been committed to your local branch, you may use the
[git-review](https://opendev.org/opendev/git-review) plugin to submit them
directly to [Gerrit](https://review.lttng.org) using the following command:

    git review

Please note that you will need to create an account on [Gerrit](https://review.lttng.org)
and add an SSH public key.

For e-mail based patches you may use Git's
[`format-patch`](https://git-scm.com/docs/git-format-patch) command
to generate a patch file. The following command line generates a
patch from the latest commit:

    git format-patch -N1 -s --subject-prefix="PATCH lttng-tools"

The custom `PATCH lttng-tools` subject prefix is mandatory when
submitting patches that apply to the LTTng-tools project.

The patch's subject (the commit message's first line) should:

  * Begin with an uppercase letter.
  * Be written in the present tense.
  * _Not_ exceed 72 characters in length.
  * _Not_ end with a period.

In the case of bug fixes, the patch's subject must be prefixed with
`Fix:` and a suitable sub-system name. For instance, a patch
addressing a bug in the session daemon should start with `Fix:
sessiond:`. Patches targeting shared code can either use the namespace
of the interface or of the internal library, whichever is more
precise.

A non-exhaustive list of common sub-system prefixes follows:

  * `relayd` (relay daemon).
  * `sessiond` (session daemon).
  * `lttng` (LTTng CLI client).
  * `ust-consumerd` (user space consumer daemon).
  * `kernel-consumerd` (kernel space consumer daemon).
  * `consumerd` (common consumer daemon).
  * `common` (internal `libcommon`).
  * `trace-chunk` (internal `lttng_trace_chunk_*` interface).
  * `lttng-ctl` (`liblttng-ctl` library).
  * `mi` (LTTng client's machine interface).

When possible, the commit title should describe the issue _as
observed_ and not the underlying cause. For instance, prefer `Fix:
sessiond: hang on SIGTERM after session rotation` to `Fix: sessiond:
unchecked status on exit`.

The commit message's body must be as detailed as possible and explain
the reasons behind the proposed change. Keep in mind that this message
will be read in a number of years and must still be clear. Any related
[bug report(s)](https://bugs.lttng.org/projects/lttng-tools/issues)
should be mentioned at the end of the message using the `#123` format,
where `123` is the bug number:

  * Use `Refs: #123` if the patch is related to bug 123, but does not
    fix it yet.
  * Use `Fixes: #123` to signify that this patch fixes the bug.

In the case of bug fixes, the following structure must be used:

  * Observed issue
  * Cause
  * Solution
  * **Optional**: Known drawbacks

A short commit message can be used when submitting typo fixes or minor
cleanups that don't introduce behaviour changes.

When submitting a patch that affects existing code, implement changes
to the existing code as prelude patches in a patch series. Explain why
those changes are needed and how they make follow-up changes
easier/possible.

Make sure to **sign-off** your submitted patches (the `-s` argument to
Git's `commit` and `format-patch` commands).

Here's a complete example:

~~~ text
Fix: relayd: missing thingy in the doodad folder on error

Observed issue
==============
After a communication error, the relay daemon will not produce
a thingy in the doodad folder. This results in the knickknack
baring the foo.

Steps to reproduce (list of commands or narrative description).

Cause
=====
The thingy_do_the_doodad() callback is only invoked when
the thread responsible for receiving messages and dispatching
them to the correct actors encounters an emoji.

However, an emoji is not guaranteed to be present in the ELF
section header [1].

Solution
========
Flushing the doodad on every reception of a thingo ensures that
the thingy is present in the doodad folder even if a communication
error occurs.

Known drawbacks
===============
Flushing the doodad too often may spam the widget and result in
degradation of the gizmo. This doesn't matter right now since
it happens exactly once per blue moon.

If this becomes a serious issue, we could machine learn the MVP
through the big O terminal.

References
==========
[1] https://www.thedocs.com/elf/proving-my-point-unambiguously.aspx

Fixes: #321
Refs: #456
Refs: #1987

Signed-off-by: Jeanne Mance <jmeance@lttng.org>
~~~

Please note that patches should be **as focused as possible**. Do not,
for instance, fix a bug and correct the indentation of an unrelated
block of code as part of the same patch.

Once you are confident your patch meets the required guidelines,
you may use Git's [`send-email`](https://git-scm.com/docs/git-send-email)
command to send your patch to the mailing list:

    git send-email --suppress-cc=self --to lttng-dev@lists.lttng.org *.patch

Make sure you are
[subscribed](http://lists.lttng.org/cgi-bin/mailman/listinfo/lttng-dev)
to the mailing list to follow and take part in discussions about your
changes. You may join the file to an email as an attachment if you can't
send the patch directly using <code>git&nbsp;send&#8209;email</code>.


## Reviews

Once your patch has been posted to the mailing list or as a GitHub
pull request, other contributors may propose modifications.
This is completely normal. This collaborative code review is an integral
part of the open source development process in general and LTTng-tools
makes no exception.

Keep in mind that reviewing patches is a time-consuming process and,
as such, may not be done right away. The delays may be affected by the
current release cycle phase and the complexity of the proposed changes.
If you think your patch might have been forgotten, please mention it on
the [`#lttng`](irc://irc.oftc.net/lttng) IRC channel or
[`@lttng` on Mastodon](https://mastodon.social/@lttng) rather than resubmitting.


## Release cycle

The LTTng-tools project follows a release cycle that alternates between
development and release candidate (RC) phases. The master branch is
feature-frozen during RC phases: only bug fixes are accepted during
this period. However, patches adding new functionality may still be
submitted and reviewed during the RC.
