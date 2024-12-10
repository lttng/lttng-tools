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


def clang_format(files):
    source_files_re = re.compile(r"^.*(\.cpp|\.hpp|\.c|\.h)$")
    files = [f for f in files if source_files_re.match(f)]
    if not files:
        return "No source files for clang-format check", 0

    logging.debug("Files for clang-format: {}".format(files))
    format_process = subprocess.Popen(
        ["clang-format", "--dry-run", "-Werror"] + files,
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
