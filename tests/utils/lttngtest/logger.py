#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

from typing import Callable, Optional


class _Logger:
    def __init__(self, log):
        # type: (Optional[Callable[[str], None]]) -> None
        self._logging_function = log  # type: Optional[Callable[[str], None]]

    def _log(self, msg):
        # type: (str) -> None
        if self._logging_function:
            self._logging_function(msg)

    @property
    def logger(self):
        # type: () -> Optional[Callable[[str], None]]
        return self._logging_function
