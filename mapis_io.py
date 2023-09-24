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

import mapis_license_notices


INTERACTIVE_COMMANDS = {
    "help": "Print this help prompt",
    "quit": "Exit the program",
    "warranty": "Show warranty information",
    "redistribution": "Show information about terms of redistribution",
    "screenshot": "Take screenshots for the previous target"
}


def read_targets_stdin():
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
            target = input(request_str).strip()
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

        yield (target, get_target_type(target))


def read_targets_file(targets_file: os.PathLike | io.TextIOBase):
    try:
        targets_file = open(targets_file, "r")
    except TypeError:
        # not a path
        pass
    # propagate OSError

    for line in targets_file:
        target = line.strip()
        target_type = get_target_type(target)
        yield (target, target_type)


def read_targets_list(targets: str):
    for target in targets.split(","):
        target_type = get_target_type(target)
        yield (target, target_type)


def get_target_type(target):
    if target in INTERACTIVE_COMMANDS.keys():
        return "command"

    try:
        socket.inet_pton(socket.AF_INET, target)
        return "address"
    except socket.error:
        pass

    if all(c in "0123456789abcdefABCDEF" for c in target):
        return "hash"

    # No matching target type
    return None
