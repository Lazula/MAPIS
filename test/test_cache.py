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

from mapis_cache import *

class TestHumanReadableSize(unittest.TestCase):
    def test_readable_to_bytes(self):
        # No units means bytes
        self.assertEqual(readable_to_bytes("300"), 300)
        
        # Base 10
        self.assertEqual(readable_to_bytes("123KB"), 123 * 1000)
        self.assertEqual(readable_to_bytes("456M"), 456 * 1000**2)
        self.assertEqual(readable_to_bytes("789G"), 789 * 1000**3)
        self.assertEqual(readable_to_bytes("147T"), 147 * 1000**4)
        self.assertEqual(readable_to_bytes("1.5K"), 1.5 * 1000)

        # Base 2
        self.assertEqual(readable_to_bytes("123KiB"), 123 * 1024)
        self.assertEqual(readable_to_bytes("456Mi"), 456 * 1024**2)
        self.assertEqual(readable_to_bytes("789GiB"), 789 * 1024**3)
        self.assertEqual(readable_to_bytes("147ti"), 147 * 1024**4)
        self.assertEqual(readable_to_bytes("1.5Ki"), 1.5 * 1024)


    def test_bytes_to_readable(self):
        self.assertEqual(bytes_to_readable(123 * 1024), "123KiB")
        self.assertEqual(bytes_to_readable(456 * 1024**2), "456MiB")
        self.assertEqual(bytes_to_readable(789 * 1024**3), "789GiB")
        self.assertEqual(bytes_to_readable(147 * 1024**4), "147TiB")
        self.assertEqual(bytes_to_readable(1.5 * 1024), "1.5KiB")
