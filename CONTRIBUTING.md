# LTTng-tools contributor's guide

Being an open source project, the LTTng-tools project welcomes
contributions from anyone. This guide walks you through the process
of contributing a patch to LTTng-tools.


## Getting the source code

The LTTng-tools project uses [Git](https://git-scm.com/) for version
control. The upstream Git repository URL is:

    git://git.lttng.org/lttng-tools.git


## Coding standard

LTTng-tools uses the
[Linux kernel coding style](http://www.kernel.org/doc/Documentation/CodingStyle)
with one addition: single-line `if`/`for`/`while` statements must be
wrapped in braces.

Example:

~~~ c
/* not good */
if (this == that)
    goto fail;

/* good */
if (this == that) {
    goto fail;
}
~~~

Although the LTTng-tools code base is primarily written in C, it does
contain shell, Perl, and Python code as well. There is no official coding
standard for these languages. However, using a style consistent with the
rest of the code written in that language is strongly encouraged.


## Creating and sending a patch

LTTng-tools's development flow is primarily email-based, although we
also accept pull requests on our
[GitHub mirror](https://github.com/lttng/lttng-tools). If you're going
to create GitHub pull requests, make sure you still follow the
guidelines below.

Like a lot of open source projects, patches are submitted and reviewed
on its development mailing list,
[`lttng-dev`](http://lists.lttng.org/cgi-bin/mailman/listinfo/lttng-dev)
(`lttng-dev@lists.lttng.org`). The mailing list is also used to share
and comment on <abbr title="Request for Comments">RFC</abbr>s and answer
user questions.

Once your changes have been committed to your local branch, you may use
Git's [`format-patch`](https://git-scm.com/docs/git-format-patch) command
to generate a patch file. The following command line generates a
patch from the latest commit:

    git format-patch -N1 -s --subject-prefix="PATCH lttng-tools"

The custom `PATCH lttng-tools` subject prefix is mandatory when
submitting patches that apply to the LTTng-tools project.

The patch's subject (the commit message's first line) should:

  * begin with an uppercase letter
  * be written in the present tense
  * _not_ exceed 72 characters in length
  * _not_ end with a period
  * be prefixed with `Fix:` if the commit fixes a bug

The commit message's body should be as detailed as possible and explain
the reasons behind the proposed change. Any related
[bug report(s)](https://bugs.lttng.org/projects/lttng-tools/issues)
should be mentioned at the end of the message using the `#123` format,
where `123` is the bug number:

  * Use `Refs: #123` if the patch is related to bug 123, but does not
    fix it yet.
  * Use `Fixes: #123` to signify that this patch fixes the bug.

Make sure to **sign-off** your submitted patches (the `-s` argument to
Git's `commit` and `format-patch` commands).

Here's a complete example:

~~~ text
Fix: use this instead of that in some context

Ball tip jowl beef ribs shankle, leberkas venison turducken tail pork
chop t-bone meatball tri-tip. Tongue beef ribs corned beef ball tip
kevin ground round sausage rump meatloaf pig meatball prosciutto
landjaeger strip steak. Pork pork belly beef.

Biltong turkey porchetta filet mignon corned beef. T-bone bresaola
shoulder meatloaf tongue kielbasa.

Fixes: #321
Refs: #456
Refs: #1987

Signed-off-by: Jeanne Mance <jmeance@lttng.org>
~~~

Please note that patches should be **as focused as possible**. Do not,
for instance, fix a bug and correct the indentation of an unrelated
block of code as part of the same patch.

The project contains a script, [`extras/checkpatch.pl`](extras/checkpatch.pl),
that performs a number of checks on a patch to ensure it is ready for
submission. Run this script on your patch and correct any reported
errors before posting it to the mailing list:

    extras/checkpatch.pl --no-tree 0001-Fix...patch

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
the [`#lttng`](irc://irc.oftc.net/lttng) IRC channel rather than
resubmitting.


## Release cycle

The LTTng-tools project follows a release cycle that alternates between
development and release candidate (RC) phases. The master branch is
feature-frozen during RC phases: only bug fixes are accepted during
this period. However, patches adding new functionality may still be
submitted and reviewed during the RC. The upcoming features and release
dates are posted in a monthly digest on the mailing list.
