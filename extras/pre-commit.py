#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2024 Kienan Stewart <kstewart@efficios.com>
#

import logging
import os
import re
import subprocess
import sys

import clang.cindex


def get_git_config_value(key, default=None):
    """
    Get a Git configuration value from the local repository.
    Returns the default value if the key is not set.
    """
    try:
        value = subprocess.check_output(
            ["git", "config", "--local", key], stderr=subprocess.DEVNULL
        ).strip()
        return value
    except subprocess.CalledProcessError:
        return default


def get_clang_format_version(clang_format_path):
    try:
        # Run the clang-format --version command
        result = subprocess.check_output(
            [clang_format_path, "--version"], text=True
        ).strip()

        # Use regex to extract the version tuple
        match = re.search(r"version (\d+)\.(\d+)\.(\d+)", result)
        if match:
            # Convert the matched groups to integers and return as a tuple
            version_tuple = tuple(map(int, match.groups()))
            return version_tuple
        else:
            logging.error("Failed to extract version from clang-format output.")
            return None
    except FileNotFoundError:
        logging.error(
            f"clang-format binary could not be found using {clang_format_path}"
        )
        return None
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to run clang-format: {e}")
        return None


def clang_format(files):
    required_clang_format_major_version = 16

    source_files_re = re.compile(r"^.*(\.cpp|\.hpp|\.c|\.h)$")
    files = [f for f in files if source_files_re.match(f)]
    if not files:
        return "No source files for clang-format check", 0

    # Extract the git config value that overrides the location of clang-format.
    # If none can be found, use the sytem's clang-format.
    clang_format_path = get_git_config_value("hooks.clangFormatPath", "clang-format")
    clang_format_version = get_clang_format_version(clang_format_path)

    if clang_format_version is None:
        return "Failed to determine clang-format version", 1

    cf_major, cf_minor, cf_patch = clang_format_version
    if cf_major != required_clang_format_major_version:
        return (
            f"Invalid clang-format version: binary `{clang_format_path}` is version {cf_major}.{cf_minor}.{cf_patch}, expected version {required_clang_format_major_version}.y.z",
            1,
        )

    logging.debug("Files for clang-format: {}".format(files))
    format_process = subprocess.Popen(
        [
            clang_format_path,
            "--dry-run",
            "-Werror",
        ]
        + files,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    stdout, _ = format_process.communicate()
    return stdout.decode("utf-8"), format_process.returncode


def clang_tidy(files):
    if not os.path.exists("compile_commands.json"):
        logging.warning("Skipping clang-tidy: compile_commands.json not found")
        logging.warning("To check with clang-tidy, run make with bear")
        return "", 0

    source_files_re = re.compile(r"(\.cpp|\.hpp|\.c|\.h)$")
    files = [f for f in files if source_files_re.match(f)]
    if not files:
        return "No source files for clang-tidy check", 0

    logging.debug("Files for clang-tidy: {}".format(files))
    tidy = subprocess.Popen(["clang-tidy"] + files, stdout=subprocess.PIPE)
    stdout, _ = tidy.communicate()
    return stdout.decode("utf-8"), tidy.returncode


def cpp_comment_style(files):
    source_files_re = re.compile(r"^.*(\.cpp|\.hpp|\.c|\.h)$")
    files = [f for f in files if source_files_re.match(f)]
    if not files:
        return "No source files for clang-format check", 0

    returncode = 0
    stdout = ""
    for file_name in files:
        idx = clang.cindex.Index.create()
        unit = idx.parse(file_name)
        for token in unit.get_tokens(extent=unit.cursor.extent):
            if token.kind != clang.cindex.TokenKind.COMMENT:
                continue
            if token.spelling:
                words = token.spelling.split()
                if words[0] != "/*" or words[-1] != "*/":
                    stdout += "Wrong comment style at {}\n{}\n".format(
                        token.extent, token.spelling
                    )
                    returncode = 1
    return stdout, returncode


def python_blacken(files):
    python_source_re = re.compile(r"^.*\.py$")
    files = [f for f in files if python_source_re.match(f)]
    if not files:
        return "No python files to check for python-black", 0

    black = subprocess.Popen(
        ["black", "--check", "--diff"] + files,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    stdout, _ = black.communicate()
    return stdout.decode("utf-8"), black.returncode


def is_text_file(filepath):
    """Check if a file is a text file using the 'file' command."""
    try:
        result = subprocess.run(
            ["file", "--mime-type", "-b", filepath],
            capture_output=True,
            text=True,
            timeout=1,
        )

        # Extract mime type before "charset" parameter which follows a semicolon
        # For example: `text/plain; charset=us-ascii`
        mime_type = result.stdout.split(";")[0].strip()
        return mime_type.startswith("text/") or mime_type in [
            "application/xml",
            "application/json",
        ]
    except Exception:
        return False


def spdx_tags(files):
    # Filter out non-text files
    files = [f for f in files if is_text_file(f)]

    tag_re = re.compile(r"SPDX-(?P<tag>[^ :]+): (?P<value>[^\n]+)")
    valid_tags = [
        "License-Identifier",
        "FileCopyrightText",
        "URL",
    ]
    stdout = ""
    returncode = 0
    for f in files:
        content = ""
        with open(f, "r") as fd:
            content = fd.read()
        has_license = False
        has_copyrighttext = False
        for m in tag_re.finditer(content):
            tag = m.group(1)
            value = m.group(2)
            if tag == "License-Identifier":
                has_license = True
            elif tag == "FileCopyrightText":
                has_copyrighttext = True
            elif tag not in valid_tags:
                stdout += "File `{}` has unknown SPDX tag `{}`\n".format(f, tag)
                # This is strict, but lttng-tools usage of SPDX is minimal
                returncode = 1
        if not has_license:
            stdout += "File `{}` is missing SPDX-License-Identifier\n".format(f)
            returncode = 1
        if not has_copyrighttext:
            stdout += "File `{}` is missing SPDX-FileCopyrightText\n".format(f)
            returncode = 1

    return stdout, returncode


if __name__ == "__main__":
    logging.basicConfig()
    failures = []

    checks = {
        "cpp-comment-style": {
            "func": cpp_comment_style,
        },
        "clang-format": {
            "func": clang_format,
        },
        "clang-tidy": {
            "func": clang_tidy,
        },
        "python-black": {
            "func": python_blacken,
        },
        "spdx": {
            "func": spdx_tags,
        },
    }

    git = subprocess.Popen(
        [
            "git",
            "diff",
            "--name-only",
            "--cached",
        ],
        stdout=subprocess.PIPE,
    )
    stdout, stderr = git.communicate()
    files = stdout.decode("utf-8").split()

    for rule_name, rule in checks.items():
        logging.info("Running rule '{}'".format(rule_name))
        stdout, returncode = rule["func"](files)
        if returncode != 0:
            failures.append(rule_name)
        checks[rule_name]["stdout"] = stdout
        checks[rule_name]["returncode"] = returncode

    for failure in failures:
        logging.error(
            "Failed rule '{}'\n{}".format(
                failure,
                checks[failure]["stdout"],
            )
        )

    # Summary
    if failures:
        logging.warning("Passed: {}".format(len(checks) - len(failures)))
        logging.error("Failed: {}".format(len(failures)))
        for failure in failures:
            logging.error("Failed rule: {}".format(failure))

    sys.exit(1 if failures else 0)
