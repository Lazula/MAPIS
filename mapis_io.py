#!/usr/bin/python3
#
# SPDX-FileCopyrightText: Copyright (C) 2020-2023 Lazula <26179473+Lazula@users.noreply.github.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# MAPIS: Multi-API Search - Identify malicious hosts and hashes
# Copyright (C) 2020-2023 Lazula <26179473+Lazula@users.noreply.github.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import colorama
import io
import os
import stat
import socket

from collections.abc import Generator

import mapis_license_notices

from mapis_types import *


def read_targets_stdin() -> Generator[Target]:
    stdin_is_pipe = stat.S_ISFIFO(os.fstat(0).st_mode)

    # Don't print license notice if not truly interactive
    if not stdin_is_pipe:
        print(mapis_license_notices.INTERACTIVE_MODE)

    while True:
        request_str = ""

        # Don't print extraneous output if getting input from a pipe
        if not stdin_is_pipe:
            request_str += f"{colorama.Fore.LIGHTCYAN_EX}{colorama.Style.BRIGHT}"
            request_str += "Input an IP address or sample hash (help for commands): "

        try:
            name = input(request_str).strip()
            # Manually reset color
            # Autoreset doesn't handle the newline from input()
            print(colorama.Style.RESET_ALL, end="")
        except EOFError:
            # Catch no ending QUIT when stdin is a pipe
            return
        except KeyboardInterrupt:
            # Catch ^C
            print("\nCaught keyboard interrupt. Exiting.")
            return

        yield Target(name, Target.deduce_type(name))


def read_targets_file(targets_file: os.PathLike | io.TextIOBase) -> Generator[Target]:
    try:
        targets_file = open(targets_file, "r")
    except TypeError:
        # not a path
        pass
    # propagate OSError

    for line in targets_file:
        name = line.strip()
        yield Target(name, Target.deduce_type(name))


def read_targets_list(targets: str) -> Generator[Target]:
    for name in targets.split(","):
        yield Target(name, Target.deduce_type(name))
