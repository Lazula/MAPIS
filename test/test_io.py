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

import unittest
import tempfile

from io import StringIO

from mapis_io import *

class TestIO(unittest.TestCase):
    targets = (
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "0000",
        "1111",
        "2222",
        "3333",
        "invalid",
        "help"
    )

    expected = (
        ("127.0.0.1", "address"),
        ("10.0.0.1", "address"),
        ("172.16.0.1", "address"),
        ("192.168.0.1", "address"),
        ("0000", "hash"),
        ("1111", "hash"),
        ("2222", "hash"),
        ("3333", "hash"),
        ("invalid", None),
        ("help", "command")
    )

    def test_read_targets_file(self):
        targets_file = tempfile.NamedTemporaryFile(mode="w+")
        targets_file.write("\n".join(self.targets))
        targets_file.seek(0)

        # Use file
        result = tuple(read_targets_file(targets_file))
        self.assertEqual(result, self.expected)

        # Use path
        # NOTE: the tempfile is removed when closed inside here
        result = tuple(read_targets_file(os.path.join(tempfile.tempdir, targets_file.name)))
        self.assertEqual(result, self.expected)
        targets_file.seek(0)


    def test_read_targets_list(self):
        result = tuple(read_targets_list(",".join(self.targets)))
        self.assertEqual(result, self.expected)


    def test_get_target_type(self):
        for target, expected_type in self.expected:
            self.assertEqual(get_target_type(target), expected_type)
