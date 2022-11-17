#!/usr/bin/env python3
#
# Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

from typing import Callable, Optional


class _Logger:
    def __init__(self, log: Optional[Callable[[str], None]]):
        self._logging_function: Optional[Callable[[str], None]] = log

    def _log(self, msg: str) -> None:
        if self._logging_function:
            self._logging_function(msg)

    @property
    def logger(self) -> Optional[Callable[[str], None]]:
        return self._logging_function
